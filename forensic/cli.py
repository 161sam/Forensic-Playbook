"""Command line interface for the Forensic Playbook framework."""

from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

import click

from . import tools as runtime_tools
from .codex import (
    CodexActionResult,
)
from .codex import (
    install as run_codex_install,
)
from .codex import (
    start as run_codex_start,
)
from .codex import (
    status as run_codex_status,
)
from .codex import (
    stop as run_codex_stop,
)
from .core.evidence import EvidenceType
from .core.framework import ForensicFramework
from .mcp import ToolExecutionResult
from .mcp.adapters import run as run_mcp_tool
from .mcp.registry import build_catalog as build_mcp_catalog
from .mcp.servers import (
    list_statuses as list_mcp_server_statuses,
)
from .mcp.servers import (
    summarise as summarise_mcp_statuses,
)
from .modules.acquisition.disk_imaging import DiskImagingModule
from .modules.acquisition.live_response import LiveResponseModule
from .modules.acquisition.memory_dump import MemoryDumpModule
from .modules.acquisition.network_capture import NetworkCaptureModule
from .modules.analysis.filesystem import FilesystemAnalysisModule
from .modules.analysis.malware import MalwareAnalysisModule
from .modules.analysis.timeline import TimelineModule
from .modules.reporting.exporter import get_pdf_renderer
from .modules.reporting.generator import ReportGenerator
from .modules.router import capture as router_capture
from .modules.router import env as router_env
from .modules.router import extract as router_extract
from .modules.router import manifest as router_manifest
from .modules.router import pipeline as router_pipeline
from .modules.router import summarize as router_summary
from .modules.triage.persistence import PersistenceModule
from .modules.triage.quick_triage import QuickTriageModule
from .modules.triage.system_info import SystemInfoModule

REPORT_FORMAT_CHOICES = ["html", "json", "md", "markdown"]
if get_pdf_renderer() is not None:
    REPORT_FORMAT_CHOICES.insert(1, "pdf")

try:  # pragma: no cover - optional legacy module
    from .modules.analysis.ioc_scanning import IoCScanner
except ModuleNotFoundError:  # pragma: no cover - optional legacy module
    IoCScanner = None  # type: ignore[assignment]


def _json_default(value: Any) -> Any:
    """Return a JSON compatible representation for complex objects."""

    if isinstance(value, Path):
        return str(value)
    return value


def _emit_status(
    ctx: click.Context,
    command: str,
    *,
    status: str,
    message: str | None = None,
    details: list[str] | None = None,
    data: Dict[str, Any] | None = None,
    errors: list[str] | None = None,
    exit_code: int | None = None,
) -> None:
    """Emit a status payload respecting ``--json`` and ``--quiet`` flags."""

    payload: Dict[str, Any] = {"command": command, "status": status}
    if message is not None:
        payload["message"] = message
    if data:
        payload["data"] = data
    if errors:
        payload["errors"] = errors

    json_mode = ctx.obj.get("json_mode", False)
    quiet = ctx.obj.get("quiet", False)

    if json_mode:
        indent = None if quiet else 2
        click.echo(
            json.dumps(payload, indent=indent, default=_json_default, sort_keys=True)
        )
    else:
        if message and (not quiet or status != "success"):
            click.echo(message, err=status == "error")
        if not quiet:
            for line in details or []:
                click.echo(line)
            if errors:
                for error in errors:
                    click.echo(f"Error: {error}", err=True)

    if exit_code is not None:
        ctx.exit(exit_code)


def _module_status_to_cli(status: str) -> tuple[str, int | None]:
    """Translate module execution status to CLI status/exit code."""

    normalized = status.lower()
    if normalized == "success":
        return "success", None
    if normalized in {"partial", "skipped"}:
        return "warning", None
    return "error", 1


def _module_result_to_dict(result: Any) -> Dict[str, Any]:
    """Return a JSON-serialisable representation of :class:`ModuleResult`."""

    return {
        "result_id": getattr(result, "result_id", ""),
        "module_name": getattr(result, "module_name", ""),
        "status": getattr(result, "status", "unknown"),
        "timestamp": getattr(result, "timestamp", ""),
        "output_path": str(getattr(result, "output_path", "") or ""),
        "findings": list(getattr(result, "findings", []) or []),
        "metadata": dict(getattr(result, "metadata", {}) or {}),
        "errors": list(getattr(result, "errors", []) or []),
    }


def _register_default_modules(ctx: click.Context) -> None:
    """Register built-in modules with guard checks."""

    framework: ForensicFramework = ctx.obj["framework"]
    skipped: Dict[str, str] = ctx.obj.setdefault("skipped_modules", {})

    def register(
        name: str,
        module_class,
        *,
        required_tools: Optional[list[str]] = None,
    ) -> None:
        if required_tools and not any(shutil.which(tool) for tool in required_tools):
            skipped[name] = f"missing tools: {', '.join(required_tools)}"
            return
        framework.register_module(name, module_class)

    register("disk_imaging", DiskImagingModule)
    register(
        "memory_dump",
        MemoryDumpModule,
        required_tools=["avml", "lime", "winpmem"],
    )
    register(
        "network_capture",
        NetworkCaptureModule,
        required_tools=["tcpdump", "dumpcap"],
    )
    register("live_response", LiveResponseModule)
    register("filesystem_analysis", FilesystemAnalysisModule)

    if IoCScanner is not None:
        register("ioc_scan", IoCScanner)
    else:
        skipped["ioc_scan"] = "module unavailable"

    register("timeline", TimelineModule)
    register("malware_analysis", MalwareAnalysisModule, required_tools=["yara"])
    register("quick_triage", QuickTriageModule)
    register("system_info", SystemInfoModule)
    register("persistence", PersistenceModule)


@click.group()
@click.option(
    "--workspace", type=click.Path(), default=None, help="Workspace directory"
)
@click.option(
    "--config", type=click.Path(exists=True), default=None, help="Config file"
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--json", "json_mode", is_flag=True, help="Emit JSON status objects")
@click.option("--quiet", is_flag=True, help="Suppress human-readable output")
@click.option(
    "--legacy/--no-legacy",
    default=False,
    help="Enable wrappers for deprecated shell scripts.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    workspace: str | None,
    config: str | None,
    verbose: bool,
    json_mode: bool,
    quiet: bool,
    legacy: bool,
) -> None:
    """Forensic Framework CLI."""

    ctx.ensure_object(dict)

    workspace_path = Path(workspace) if workspace else None
    config_path = Path(config) if config else None

    # Quiet mode takes precedence over verbose output to avoid mixed messaging.
    effective_verbose = verbose and not quiet

    ctx.obj["framework"] = ForensicFramework(
        config_file=config_path, workspace=workspace_path
    )
    ctx.obj["verbose"] = effective_verbose
    ctx.obj["skipped_modules"] = {}
    ctx.obj["legacy_enabled"] = legacy
    ctx.obj["json_mode"] = json_mode
    ctx.obj["quiet"] = quiet

    _register_default_modules(ctx)


def _emit_codex_result(
    ctx: click.Context, command: str, result: CodexActionResult
) -> None:
    details = list(result.details)
    if result.warnings:
        details.append("Warnings:")
        details.extend(f"  - {warning}" for warning in result.warnings)

    data = dict(result.data)
    if result.warnings and "warnings" not in data:
        data["warnings"] = result.warnings
    if result.errors and "errors" not in data:
        data["errors"] = result.errors

    exit_code = 1 if result.status == "error" else None

    _emit_status(
        ctx,
        command,
        status=result.status,
        message=result.message,
        details=details,
        data=data,
        errors=result.errors,
        exit_code=exit_code,
    )


def _emit_mcp_tool_result(
    ctx: click.Context, command: str, tool: str, result: ToolExecutionResult
) -> None:
    pretty_details = [f"Tool: {tool}"]
    if result.data:
        pretty_details.append(
            "Result data keys: " + ", ".join(sorted(result.data.keys()))
        )
    if result.warnings:
        pretty_details.append("Warnings:")
        pretty_details.extend(f"  - {warning}" for warning in result.warnings)

    exit_code = 1 if result.status == "error" else None
    payload = result.to_dict()

    _emit_status(
        ctx,
        command,
        status=result.status,
        message=result.message,
        details=pretty_details,
        data={"tool": tool, "result": payload},
        errors=result.errors,
        exit_code=exit_code,
    )


def _coerce_argument_value(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _parse_key_value_pairs(pairs: tuple[str, ...]) -> Dict[str, Any]:
    arguments: Dict[str, Any] = {}
    for item in pairs:
        if "=" not in item:
            raise click.BadParameter(
                f"Invalid argument '{item}'. Use key=value syntax."
            )
        key, value = item.split("=", 1)
        arguments[key] = _coerce_argument_value(value)
    return arguments


@cli.group()
def codex() -> None:
    """Guarded helpers for the Codex + MCP workflow."""


@codex.command("install")
@click.option(
    "--workspace",
    type=click.Path(path_type=Path),
    default=None,
    help="Workspace directory (defaults to CLI context or /mnt/usb_rw)",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    help="Preview installer actions without executing (default).",
)
@click.option(
    "--accept-risk",
    is_flag=True,
    help="Acknowledge guarded actions and execute the installer script.",
)
@click.pass_context
def codex_install(
    ctx: click.Context,
    workspace: Path | None,
    dry_run: bool,
    accept_risk: bool,
) -> None:
    """Install or update the Codex forensic environment."""

    framework_workspace = Path(ctx.obj["framework"].workspace)
    target_workspace = workspace or framework_workspace
    result = run_codex_install(
        workspace=target_workspace,
        dry_run=dry_run,
        accept_risk=accept_risk,
        env=os.environ,
    )
    _emit_codex_result(ctx, "codex.install", result)


@codex.command("start")
@click.option(
    "--workspace",
    type=click.Path(path_type=Path),
    default=None,
    help="Workspace directory (defaults to CLI context or /mnt/usb_rw)",
)
@click.option(
    "--foreground",
    is_flag=True,
    help="Stream start script output in the foreground during execution.",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    help="Preview start actions without executing (default).",
)
@click.pass_context
def codex_start(
    ctx: click.Context,
    workspace: Path | None,
    foreground: bool,
    dry_run: bool,
) -> None:
    """Start the guarded MCP server for Codex."""

    framework_workspace = Path(ctx.obj["framework"].workspace)
    target_workspace = workspace or framework_workspace
    result = run_codex_start(
        workspace=target_workspace,
        dry_run=dry_run,
        foreground=foreground,
        env=os.environ,
    )
    _emit_codex_result(ctx, "codex.start", result)


@codex.command("stop")
@click.option(
    "--workspace",
    type=click.Path(path_type=Path),
    default=None,
    help="Workspace directory (defaults to CLI context or /mnt/usb_rw)",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    help="Preview stop actions without executing (default).",
)
@click.pass_context
def codex_stop(
    ctx: click.Context,
    workspace: Path | None,
    dry_run: bool,
) -> None:
    """Stop the Codex MCP server if a PID file is present."""

    framework_workspace = Path(ctx.obj["framework"].workspace)
    target_workspace = workspace or framework_workspace
    result = run_codex_stop(
        workspace=target_workspace,
        dry_run=dry_run,
        env=os.environ,
    )
    _emit_codex_result(ctx, "codex.stop", result)


@codex.command("status")
@click.option(
    "--workspace",
    type=click.Path(path_type=Path),
    default=None,
    help="Workspace directory (defaults to CLI context or /mnt/usb_rw)",
)
@click.pass_context
def codex_status(ctx: click.Context, workspace: Path | None) -> None:
    """Report the status of the Codex MCP server and log metadata."""

    framework_workspace = Path(ctx.obj["framework"].workspace)
    target_workspace = workspace or framework_workspace
    result = run_codex_status(
        workspace=target_workspace,
        env=os.environ,
    )
    _emit_codex_result(ctx, "codex.status", result)


@cli.group()
def mcp() -> None:
    """Interact with MCP servers and tool adapters."""


@mcp.command("expose")
@click.option(
    "--compact",
    is_flag=True,
    help="Emit compact JSON without indentation",
)
@click.option(
    "--out",
    "output_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Write catalogue to file instead of stdout.",
)
@click.pass_context
def mcp_expose(ctx: click.Context, compact: bool, output_file: Path | None) -> None:
    """Print (or persist) the MCP tool catalogue as JSON."""

    framework: ForensicFramework = ctx.obj["framework"]
    payload = build_mcp_catalog(framework)
    indent = None if compact else 2
    rendered = json.dumps(payload, indent=indent, sort_keys=True)

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(rendered + "\n", encoding="utf-8")
        click.echo(str(output_file))
        return

    click.echo(rendered)


@mcp.command("status")
@click.pass_context
def mcp_status(ctx: click.Context) -> None:
    """Report availability of built-in MCP server connectors."""

    statuses = list_mcp_server_statuses()
    summary = summarise_mcp_statuses(statuses)
    details = []
    for entry in summary["statuses"]:
        message = entry.get("message")
        label = f"{entry['name']}: {entry['status']}"
        if message:
            label = f"{label} – {message}"
        details.append(label)

    overall = summary["overall"]
    if overall == "success":
        status = "success"
        message = "MCP connectors available"
        exit_code = None
    elif overall == "warning":
        status = "warning"
        message = "Some MCP connectors are not yet configured"
        exit_code = None
    else:
        status = "error"
        message = "One or more MCP connectors unavailable"
        exit_code = 1

    _emit_status(
        ctx,
        "mcp.status",
        status=status,
        message=message,
        details=details,
        data={"servers": summary["statuses"]},
        exit_code=exit_code,
    )


@mcp.command("run")
@click.argument("tool")
@click.option(
    "--arg",
    "arguments",
    multiple=True,
    help="Tool argument as key=value (repeat for multiple entries)",
)
@click.option(
    "--local",
    is_flag=True,
    help="Execute via in-process adapters instead of remote connectors",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    help="Keep execution in dry-run mode when supported (default: enabled)",
)
@click.pass_context
def mcp_run(
    ctx: click.Context,
    tool: str,
    arguments: tuple[str, ...],
    local: bool,
    dry_run: bool,
) -> None:
    """Execute an MCP tool via the adapter layer."""

    framework: ForensicFramework = ctx.obj["framework"]
    parsed_arguments = _parse_key_value_pairs(arguments)

    result = run_mcp_tool(
        framework,
        tool,
        parsed_arguments,
        local=local,
        dry_run=dry_run,
    )

    command = "mcp.run.local" if local else "mcp.run.remote"
    _emit_mcp_tool_result(ctx, command, tool, result)


@cli.group()
def case() -> None:
    """Case management commands."""


@case.command("create")
@click.argument("name")
@click.option("--description", "-d", default="", help="Case description")
@click.option("--investigator", "-i", required=True, help="Investigator name")
@click.option("--case-id", default=None, help="Custom case ID")
@click.pass_context
def create_case(
    ctx: click.Context,
    name: str,
    description: str,
    investigator: str,
    case_id: Optional[str],
) -> None:
    """Create a new case."""

    framework: ForensicFramework = ctx.obj["framework"]

    case = framework.create_case(
        name=name, description=description, investigator=investigator, case_id=case_id
    )
    data = {
        "case_id": case.case_id,
        "name": case.name,
        "description": case.description,
        "investigator": case.investigator,
        "directory": str(case.case_dir),
    }
    details = [
        f"  Name: {case.name}",
        f"  Directory: {case.case_dir}",
    ]
    _emit_status(
        ctx,
        "case.create",
        status="success",
        message=f"✓ Case created: {case.case_id}",
        details=details,
        data={"case": data},
    )


@case.command("init")
@click.argument("case_id", default="demo")
@click.option("--name", default=None, help="Human friendly case name")
@click.option(
    "--description",
    default="Demo case scaffold generated via 'case init'",
    help="Case description",
)
@click.option(
    "--investigator",
    default="Demo Analyst",
    help="Investigator responsible for the case",
)
@click.option(
    "--force",
    is_flag=True,
    help="Re-use existing case directory if it already exists",
)
@click.pass_context
def init_case(
    ctx: click.Context,
    case_id: str,
    name: str | None,
    description: str,
    investigator: str,
    force: bool,
) -> None:
    """Scaffold a minimal investigation case for quick demos."""

    framework: ForensicFramework = ctx.obj["framework"]

    if not name:
        name = case_id.replace("_", " ").title()

    try:
        case = framework.load_case(case_id)
        existed = True
    except ValueError:
        existed = False
        case = framework.create_case(
            name=name,
            description=description,
            investigator=investigator,
            case_id=case_id,
        )

    if existed and not force:
        details = [f"  Directory: {case.case_dir}"]
        data = {
            "case_id": case.case_id,
            "name": case.name,
            "directory": str(case.case_dir),
            "existed": True,
        }
        _emit_status(
            ctx,
            "case.init",
            status="warning",
            message=f"✓ Case already initialised: {case.case_id}",
            details=details,
            data=data,
        )
        return

    # Ensure the common sub-directories are present.
    for subdir in ("evidence", "analysis", "reports", "logs"):
        (case.case_dir / subdir).mkdir(parents=True, exist_ok=True)

    details = [f"  Directory: {case.case_dir}"]
    data = {
        "case_id": case.case_id,
        "name": case.name,
        "directory": str(case.case_dir),
        "existed": existed,
    }
    _emit_status(
        ctx,
        "case.init",
        status="success",
        message=f"✓ Case initialised: {case.case_id}",
        details=details,
        data=data,
    )


@case.command("list")
@click.pass_context
def list_cases(ctx: click.Context) -> None:
    """List all cases."""

    framework: ForensicFramework = ctx.obj["framework"]
    cases = framework.list_cases()

    if not cases:
        _emit_status(
            ctx,
            "case.list",
            status="success",
            message="No cases found",
            data={"cases": []},
        )
        return

    details = ["Cases:"]
    for case in cases:
        details.append(f"  {case['case_id']}: {case['name']}")
        details.append(f"    Investigator: {case['investigator']}")
        details.append(f"    Created: {case['created_at']}")
        details.append("")

    _emit_status(
        ctx,
        "case.list",
        status="success",
        message=f"{len(cases)} case(s) found",
        details=details,
        data={"cases": cases},
    )


@case.command("load")
@click.argument("case_id")
@click.pass_context
def load_case(ctx: click.Context, case_id: str) -> None:
    """Load an existing case."""

    framework: ForensicFramework = ctx.obj["framework"]

    try:
        case = framework.load_case(case_id)
    except ValueError as exc:
        _emit_status(
            ctx,
            "case.load",
            status="error",
            message=f"✗ Error: {exc}",
            errors=[str(exc)],
            exit_code=1,
        )
        return

    details = [
        f"  Name: {case.name}",
        f"  Directory: {case.case_dir}",
    ]
    data = {
        "case_id": case.case_id,
        "name": case.name,
        "directory": str(case.case_dir),
        "description": case.description,
        "investigator": case.investigator,
    }
    _emit_status(
        ctx,
        "case.load",
        status="success",
        message=f"✓ Case loaded: {case.case_id}",
        details=details,
        data={"case": data},
    )


@cli.group()
def evidence() -> None:
    """Evidence management commands."""


@evidence.command("add")
@click.argument("source_path", type=click.Path(exists=True))
@click.option(
    "--type",
    "-t",
    "evidence_type",
    type=click.Choice(["disk", "memory", "network", "file", "log", "other"]),
    required=True,
    help="Evidence type",
)
@click.option("--description", "-d", required=True, help="Evidence description")
@click.pass_context
def add_evidence(
    ctx: click.Context,
    source_path: str,
    evidence_type: str,
    description: str,
) -> None:
    """Add evidence to the current case."""

    framework: ForensicFramework = ctx.obj["framework"]

    if not framework.current_case:
        message = "✗ No active case. Load or create a case first."
        _emit_status(
            ctx,
            "evidence.add",
            status="error",
            message=message,
            errors=[message],
            exit_code=1,
        )
        return

    evidence_type_enum = EvidenceType[evidence_type.upper()]

    evidence = framework.add_evidence(
        evidence_type=evidence_type_enum,
        source_path=Path(source_path),
        description=description,
    )
    details = [
        f"  Type: {evidence.evidence_type.value}",
        f"  Hash: {evidence.hash_sha256}",
    ]
    data = {
        "evidence_id": evidence.evidence_id,
        "type": evidence.evidence_type.value,
        "hash_sha256": evidence.hash_sha256,
        "source_path": str(evidence.source_path),
    }
    _emit_status(
        ctx,
        "evidence.add",
        status="success",
        message=f"✓ Evidence added: {evidence.evidence_id}",
        details=details,
        data={"evidence": data},
    )


@cli.group()
def modules() -> None:
    """Module operations."""


@modules.command("list")
@click.pass_context
def list_modules(ctx: click.Context) -> None:
    """List available modules."""

    framework: ForensicFramework = ctx.obj["framework"]
    available = sorted(framework.list_modules())
    skipped = ctx.obj.get("skipped_modules", {})

    details = ["Available modules:"]
    details.extend(f"  • {module_name}" for module_name in available)
    if skipped:
        details.append("")
        details.append("Unavailable modules:")
        for module_name, reason in skipped.items():
            details.append(f"  • {module_name} ({reason})")

    data = {"available": available, "unavailable": skipped}
    _emit_status(
        ctx,
        "modules.list",
        status="success",
        message=f"{len(available)} module(s) available",
        details=details,
        data=data,
    )


@modules.command("run")
@click.argument("module_name")
@click.option("--case", "case_id", help="Case identifier to load before execution")
@click.option(
    "--root",
    "root_path",
    type=click.Path(path_type=Path),
    help="Root path or evidence source for the module",
)
@click.option(
    "--out",
    "out_path",
    type=click.Path(path_type=Path),
    help="Override default output path",
)
@click.option("--tz", "timezone", help="Timezone override passed to the module")
@click.option("--dry-run", is_flag=True, help="Execute the module in dry-run mode")
@click.option(
    "--enable-live-capture",
    is_flag=True,
    help="Allow modules to perform live capture actions",
)
@click.option("--param", multiple=True, type=str, help="Module parameter key=value")
@click.pass_context
def run_module(
    ctx: click.Context,
    module_name: str,
    case_id: str | None,
    root_path: Path | None,
    out_path: Path | None,
    timezone: str | None,
    dry_run: bool,
    enable_live_capture: bool,
    param: tuple[str, ...],
) -> None:
    """Run a module with optional parameters."""

    framework: ForensicFramework = ctx.obj["framework"]
    params: Dict[str, Any] = {}

    for item in param:
        if "=" not in item:
            message = f"✗ Invalid parameter '{item}'. Use key=value format."
            _emit_status(
                ctx,
                "modules.run",
                status="error",
                message=message,
                errors=[message],
                exit_code=1,
            )
            return
        key, value = item.split("=", 1)
        params[key] = value

    if dry_run:
        params["dry_run"] = True
    if enable_live_capture:
        params["enable_live_capture"] = True
    if timezone:
        params["timezone"] = timezone
    if root_path is not None:
        root_str = str(root_path)
        for key in ("root", "source", "target", "image", "path", "mount"):
            params.setdefault(key, root_str)
    if out_path is not None:
        out_str = str(out_path)
        params.setdefault("output", out_str)
        params["output_file"] = out_str

    if case_id:
        try:
            case = framework.load_case(case_id)
        except ValueError as exc:
            _emit_status(
                ctx,
                "modules.run",
                status="error",
                message=f"✗ {exc}",
                errors=[str(exc)],
                exit_code=1,
            )
            return
    else:
        case = framework.current_case
        if case is None:
            message = "✗ No active case. Use --case to select one."
            _emit_status(
                ctx,
                "modules.run",
                status="error",
                message=message,
                errors=[message],
                exit_code=1,
            )
            return

    try:
        result = framework.execute_module(module_name, params=params)
    except ValueError as exc:
        _emit_status(
            ctx,
            "modules.run",
            status="error",
            message=f"✗ {exc}",
            errors=[str(exc)],
            exit_code=1,
        )
        return
    except RuntimeError as exc:
        _emit_status(
            ctx,
            "modules.run",
            status="error",
            message=f"✗ {exc}",
            errors=[str(exc)],
            exit_code=1,
        )
        return
    except Exception as exc:  # pragma: no cover - defensive
        message = f"✗ Module execution failed: {exc}"
        _emit_status(
            ctx,
            "modules.run",
            status="error",
            message=message,
            errors=[str(exc)],
            exit_code=1,
        )
        return

    module_payload = _module_result_to_dict(result)
    cli_status, exit_code = _module_status_to_cli(module_payload["status"])
    message = f"Module {module_name} finished with status: {module_payload['status']}"

    details: list[str] = [f"Status: {module_payload['status']}"]
    if module_payload.get("output_path"):
        details.append(f"Output file: {module_payload['output_path']}")
    if module_payload["findings"]:
        details.append("Findings:")
        for finding in module_payload["findings"]:
            if isinstance(finding, dict):
                description = finding.get("description") or json.dumps(
                    finding, default=_json_default, sort_keys=True
                )
            else:
                description = str(finding)
            details.append(f"  - {description}")
    if module_payload["errors"]:
        details.append("Errors:")
        for error in module_payload["errors"]:
            details.append(f"  - {error}")

    params_payload = {
        key: (str(value) if isinstance(value, Path) else value)
        for key, value in params.items()
    }
    data = {
        "case_id": getattr(case, "case_id", None),
        "module": module_name,
        "params": params_payload,
        "result": module_payload,
    }

    _emit_status(
        ctx,
        "modules.run",
        status=cli_status,
        message=message,
        details=details,
        data=data,
        errors=module_payload["errors"] if cli_status == "error" else None,
        exit_code=exit_code,
    )


cli.add_command(modules, name="module")


@cli.group()
def report() -> None:
    """Reporting commands."""


@report.command("generate")
@click.option(
    "--fmt",
    type=click.Choice(REPORT_FORMAT_CHOICES),
    default="md",
    show_default=True,
    help="Report output format.",
)
@click.option(
    "--out",
    "out_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Output file path",
)
@click.option("--case", "case_id", required=True, help="Case identifier")
@click.option(
    "--dry-run", is_flag=True, help="Prepare report data without writing files"
)
@click.pass_context
def generate_report(
    ctx: click.Context,
    fmt: str,
    out_path: Path | None,
    case_id: str,
    dry_run: bool,
) -> None:
    """Generate a case report using the reporting module."""

    framework: ForensicFramework = ctx.obj["framework"]

    try:
        case = framework.load_case(case_id)
    except ValueError as exc:
        _emit_status(
            ctx,
            "report.generate",
            status="error",
            message=f"✗ Error: {exc}",
            errors=[str(exc)],
            exit_code=1,
        )
        return

    params: Dict[str, Any] = {"format": fmt}
    if out_path:
        params["output_file"] = str(out_path)
    if dry_run:
        params["dry_run"] = True

    module = ReportGenerator(case_dir=case.case_dir, config=framework.config)
    result = module.run(None, params)

    payload = _module_result_to_dict(result)
    cli_status, exit_code = _module_status_to_cli(payload["status"])
    message = f"Report generation status: {payload['status']}"

    details = [f"Status: {payload['status']}"]
    if payload.get("output_path"):
        details.append(f"Output file: {payload['output_path']}")
    if payload["metadata"].get("dry_run"):
        details.append("Dry-run mode: no files were written.")
    if payload["findings"]:
        details.append("Findings:")
        for finding in payload["findings"]:
            if isinstance(finding, dict):
                description = finding.get("description") or json.dumps(
                    finding, default=_json_default, sort_keys=True
                )
            else:
                description = str(finding)
            details.append(f"  - {description}")
    if payload["errors"]:
        details.append("Errors:")
        for error in payload["errors"]:
            details.append(f"  - {error}")

    params_payload = {
        key: (str(value) if isinstance(value, Path) else value)
        for key, value in params.items()
    }
    data = {
        "case_id": case.case_id,
        "params": params_payload,
        "result": payload,
    }

    _emit_status(
        ctx,
        "report.generate",
        status=cli_status,
        message=message,
        details=details,
        data=data,
        errors=payload["errors"] if cli_status == "error" else None,
        exit_code=exit_code,
    )


@cli.command()
@click.pass_context
def diagnostics(ctx: click.Context) -> None:
    """Display environment diagnostics and guard information."""

    framework: ForensicFramework = ctx.obj["framework"]
    workspace = framework.workspace

    tz_info = datetime.now().astimezone().tzinfo
    paths_to_check = [workspace, workspace / "analysis", workspace / "reports"]

    path_details: list[Dict[str, Any]] = []
    path_lines = ["Write permissions:"]
    for path in paths_to_check:
        exists = path.exists()
        writable = os.access(path if exists else path.parent, os.W_OK)
        status = "✓" if writable else "✗"
        suffix = "exists" if exists else "will be created"
        path_lines.append(f"  {status} {path} ({suffix})")
        path_details.append(
            {
                "path": str(path),
                "exists": exists,
                "writable": writable,
                "note": suffix,
            }
        )

    tool_groups = {
        "Network capture": ["tcpdump", "dumpcap"],
        "Timeline tooling": ["log2timeline.py", "mactime"],
        "Sleuthkit": ["fls"],
        "Memory acquisition": ["avml", "lime", "winpmem"],
        "YARA": ["yara"],
    }

    tool_details: Dict[str, Dict[str, list[str]]] = {}
    tool_lines = ["Tool availability:"]
    for label, tools in tool_groups.items():
        available = sorted(tool for tool in tools if shutil.which(tool))
        missing = sorted(tool for tool in tools if tool not in available)
        parts = []
        if available:
            parts.append(f"available: {', '.join(available)}")
        if missing:
            parts.append(f"missing: {', '.join(missing)}")
        message = "; ".join(parts) if parts else "no tools detected"
        tool_lines.append(f"  - {label}: {message}")
        tool_details[label] = {"available": available, "missing": missing}

    wrapper_details: Dict[str, Dict[str, Any]] = {}
    wrapper_lines = ["Tool wrappers (guarded):"]
    for wrapper_name in sorted(runtime_tools.__all__):
        wrapper = getattr(runtime_tools, wrapper_name)
        try:
            wrapper_available = bool(wrapper.available())
        except Exception as exc:  # pragma: no cover - defensive diagnostics
            wrapper_available = False
            availability_note = f"error: {exc}"
        else:
            availability_note = "available" if wrapper_available else "missing"

        try:
            wrapper_version = wrapper.version() if wrapper_available else None
        except Exception:  # pragma: no cover - defensive diagnostics
            wrapper_version = None

        try:
            wrapper_requirements = list(wrapper.requirements())
        except Exception:  # pragma: no cover - defensive diagnostics
            wrapper_requirements = []

        try:
            wrapper_capabilities = list(wrapper.capabilities())
        except Exception:  # pragma: no cover - defensive diagnostics
            wrapper_capabilities = []

        version_note = wrapper_version or "n/a"
        line = f"  - {wrapper_name}: {availability_note} (version: {version_note})"
        wrapper_lines.append(line)
        if wrapper_requirements and not wrapper_available:
            wrapper_lines.append(f"    requirements: {', '.join(wrapper_requirements)}")

        wrapper_details[wrapper_name] = {
            "available": wrapper_available,
            "version": wrapper_version,
            "requirements": wrapper_requirements,
            "capabilities": wrapper_capabilities,
        }

    optional_packages = {
        "volatility3": "volatility3",
        "pyshark": "pyshark",
        "yara-python": "yara",
    }

    package_details: Dict[str, str] = {}
    package_lines = ["Python packages:"]
    for label, module_name in optional_packages.items():
        try:
            importlib.import_module(module_name)
            status = "available"
        except ModuleNotFoundError:
            status = "missing"
        package_lines.append(f"  - {label}: {status}")
        package_details[label] = status

    skipped_modules = ctx.obj.get("skipped_modules", {})
    available_modules = sorted(framework.list_modules())
    guard_status = "OK" if not skipped_modules else "Missing"
    guard_lines = [f"Guards: {guard_status}"]
    if skipped_modules:
        guard_lines.append("  Missing modules:")
        for module_name, reason in sorted(skipped_modules.items()):
            guard_lines.append(f"    - {module_name}: {reason}")
    else:
        guard_lines.append("  All registered modules passed guard checks.")

    details = [
        "=== Environment diagnostics ===",
        f"Timezone: {tz_info}",
        f"Workspace: {workspace}",
        "",
        *path_lines,
        "",
        *tool_lines,
        "",
        *wrapper_lines,
        "",
        *package_lines,
        "",
        *guard_lines,
        "",
        "Diagnostics complete.",
    ]

    data = {
        "timezone": str(tz_info),
        "workspace": str(workspace),
        "paths": path_details,
        "tools": tool_details,
        "tool_wrappers": wrapper_details,
        "python_packages": package_details,
        "module_guards": {
            "status": guard_status,
            "available": available_modules,
            "missing": skipped_modules,
        },
    }

    _emit_status(
        ctx,
        "diagnostics",
        status="success",
        message="Diagnostics collected",
        details=details,
        data=data,
    )


def _router_emit(ctx: click.Context, command: str, result) -> None:
    """Bridge :class:`RouterResult` payloads to the CLI status handler."""

    payload = result.to_cli_kwargs()
    _emit_status(
        ctx,
        command,
        status=payload.get("status", "success"),
        message=payload.get("message"),
        details=payload.get("details"),
        data=payload.get("data"),
        errors=payload.get("errors"),
    )


@cli.group()
@click.pass_context
def router(ctx: click.Context) -> None:
    """Router forensic workflow helpers with dry-run safeguards."""

    ctx.ensure_object(dict)


def _load_router_case(ctx: click.Context, command: str, case_id: str):
    framework: ForensicFramework = ctx.obj["framework"]
    try:
        return framework.load_case(case_id)
    except ValueError as exc:
        message = f"✗ {exc}"
        _emit_status(
            ctx,
            command,
            status="error",
            message=message,
            errors=[str(exc)],
            exit_code=1,
        )
        return None


def _resolve_router_case(
    ctx: click.Context,
    command: str,
    case_id: str | None,
    *,
    root: Path | None = None,
):
    if case_id:
        return _load_router_case(ctx, command, case_id)

    framework: ForensicFramework = ctx.obj["framework"]
    workspace = Path(framework.workspace or Path.cwd())
    fallback_root = root or workspace / "router"
    return SimpleNamespace(case_id="router-ad-hoc", case_dir=fallback_root)


def _collect_router_params(
    ctx: click.Context,
    command: str,
    *,
    case,
    dry_run: bool,
    extra: Dict[str, Any] | None = None,
    param: tuple[str, ...] = (),
) -> Dict[str, Any] | None:
    try:
        parsed = _parse_key_value_pairs(param)
    except click.BadParameter as exc:
        message = f"✗ {exc}"
        _emit_status(
            ctx,
            command,
            status="error",
            message=message,
            errors=[str(exc)],
            exit_code=1,
        )
        return None

    params: Dict[str, Any] = dict(parsed)
    if extra:
        params.update({key: value for key, value in extra.items() if value is not None})

    params["case"] = case.case_dir
    params["case_id"] = case.case_id
    params["dry_run"] = dry_run
    return params


@router.group(name="env")
def router_env_group() -> None:
    """Environment preparation commands."""


@router_env_group.command("init")
@click.option(
    "--case",
    "case_id",
    default=None,
    help="Optional case identifier to scope router outputs",
)
@click.option(
    "--root",
    type=click.Path(path_type=Path),
    default=None,
    help="Optional override for the router workspace root",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    show_default=True,
    help="Preview environment setup without writing to disk.",
)
@click.pass_context
def router_env_init(
    ctx: click.Context,
    case_id: str | None,
    root: Path | None,
    dry_run: bool,
) -> None:
    """Initialise the router workspace layout for a case."""

    case = _resolve_router_case(ctx, "router env init", case_id, root=root)
    if case is None:
        return

    params: Dict[str, Any] = {
        "case": case.case_dir,
        "case_id": case.case_id,
        "dry_run": dry_run,
    }
    if root:
        params["root"] = root

    result = router_env.init_environment(params)
    _router_emit(ctx, "router env init", result)


@router.group(name="capture")
def router_capture_group() -> None:
    """Guarded router capture helpers."""


@router_capture_group.command("setup")
@click.option(
    "--case",
    "case_id",
    default=None,
    help="Optional case identifier for capture planning",
)
@click.option(
    "--param",
    "param",
    multiple=True,
    type=str,
    help="Override capture parameters (key=value).",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    show_default=True,
    help="Preview capture setup without filesystem changes.",
)
@click.pass_context
def router_capture_setup(
    ctx: click.Context,
    case_id: str | None,
    param: tuple[str, ...],
    dry_run: bool,
) -> None:
    """Prepare capture directories under the case workspace."""

    case = _resolve_router_case(ctx, "router capture setup", case_id)
    if case is None:
        return

    params = _collect_router_params(
        ctx,
        "router capture setup",
        case=case,
        dry_run=dry_run,
        param=param,
    )
    if params is None:
        return

    result = router_capture.setup(params)
    _router_emit(ctx, "router capture setup", result)


@router_capture_group.command("start")
@click.option(
    "--case",
    "case_id",
    default=None,
    help="Optional case identifier for capture execution",
)
@click.option(
    "--if", "interface", type=str, default=None, help="Network interface to monitor"
)
@click.option("--duration", type=int, default=None, help="Capture duration in seconds")
@click.option("--bpf", type=str, default=None, help="Optional BPF filter expression")
@click.option(
    "--pcap-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory for PCAP output",
)
@click.option(
    "--meta-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory for capture metadata",
)
@click.option("--tool", type=str, default=None, help="Capture binary to use")
@click.option(
    "--enable-live-capture",
    is_flag=True,
    help="Perform a real capture instead of a dry-run preview",
)
@click.option(
    "--param",
    "param",
    multiple=True,
    type=str,
    help="Additional capture parameter override (key=value).",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    show_default=True,
    help="Preview capture start without executing commands.",
)
@click.pass_context
def router_capture_start(
    ctx: click.Context,
    case_id: str | None,
    interface: str | None,
    duration: int | None,
    bpf: str | None,
    pcap_dir: Path | None,
    meta_dir: Path | None,
    tool: str | None,
    enable_live_capture: bool,
    param: tuple[str, ...],
    dry_run: bool,
) -> None:
    """Stage or execute a guarded router capture."""

    case = _resolve_router_case(ctx, "router capture start", case_id)
    if case is None:
        return

    extra: Dict[str, Any] = {
        "interface": interface,
        "duration": duration,
        "bpf": bpf,
        "pcap_dir": str(pcap_dir) if pcap_dir else None,
        "meta_dir": str(meta_dir) if meta_dir else None,
        "tool": tool,
        "enable_live_capture": enable_live_capture,
    }

    params = _collect_router_params(
        ctx,
        "router capture start",
        case=case,
        dry_run=dry_run,
        extra=extra,
        param=param,
    )
    if params is None:
        return

    result = router_capture.start(params)
    _router_emit(ctx, "router capture start", result)


@router_capture_group.command("stop")
@click.option(
    "--case",
    "case_id",
    default=None,
    help="Optional case identifier for stopping captures",
)
@click.option(
    "--param",
    "param",
    multiple=True,
    type=str,
    help="Additional stop parameter override (key=value).",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    show_default=True,
    help="Preview stop guidance without terminating processes.",
)
@click.pass_context
def router_capture_stop(
    ctx: click.Context,
    case_id: str | None,
    param: tuple[str, ...],
    dry_run: bool,
) -> None:
    """Provide guarded guidance for stopping router captures."""

    case = _resolve_router_case(ctx, "router capture stop", case_id)
    if case is None:
        return

    params = _collect_router_params(
        ctx,
        "router capture stop",
        case=case,
        dry_run=dry_run,
        param=param,
    )
    if params is None:
        return

    result = router_capture.stop(params)
    _router_emit(ctx, "router capture stop", result)


@router.group(name="extract")
def router_extract_group() -> None:
    """Router artifact extraction helpers."""


@router_extract_group.command("ui")
@click.option(
    "--case",
    "case_id",
    default=None,
    help="Optional case identifier for extraction",
)
@click.option(
    "--param",
    "param",
    multiple=True,
    type=str,
    help="Extraction parameter override (key=value).",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    show_default=True,
    help="Preview extraction steps without writing output.",
)
@click.pass_context
def router_extract_ui(
    ctx: click.Context,
    case_id: str | None,
    param: tuple[str, ...],
    dry_run: bool,
) -> None:
    """Extract router UI artefacts into the case workspace."""

    case = _resolve_router_case(ctx, "router extract ui", case_id)
    if case is None:
        return

    params = _collect_router_params(
        ctx,
        "router extract ui",
        case=case,
        dry_run=dry_run,
        extra={"kind": "ui"},
        param=param,
    )
    if params is None:
        return

    result = router_extract.extract("ui", params)
    _router_emit(ctx, "router extract ui", result)


@router.group(name="manifest")
def router_manifest_group() -> None:
    """Evidence manifest helpers."""


@router_manifest_group.command("write")
@click.option(
    "--case",
    "case_id",
    default=None,
    help="Optional case identifier for manifest generation",
)
@click.option(
    "--param",
    "param",
    multiple=True,
    type=str,
    help="Manifest parameter override (key=value).",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    show_default=True,
    help="Preview manifest generation without writing files.",
)
@click.pass_context
def router_manifest_write(
    ctx: click.Context,
    case_id: str | None,
    param: tuple[str, ...],
    dry_run: bool,
) -> None:
    """Generate a deterministic manifest for router artifacts."""

    case = _resolve_router_case(ctx, "router manifest write", case_id)
    if case is None:
        return

    params = _collect_router_params(
        ctx,
        "router manifest write",
        case=case,
        dry_run=dry_run,
        param=param,
    )
    if params is None:
        return

    result = router_manifest.write_manifest(params)
    _router_emit(ctx, "router manifest write", result)


@router.group(name="pipeline")
def router_pipeline_group() -> None:
    """Router pipeline orchestration commands."""


@router_pipeline_group.command("run")
@click.option(
    "--case",
    "case_id",
    default=None,
    help="Optional case identifier for pipeline execution",
)
@click.option(
    "--with-capture",
    is_flag=True,
    help="Include the capture step (requires guarded enablement).",
)
@click.option(
    "--param",
    "param",
    multiple=True,
    type=str,
    help="Pipeline parameter override (key=value).",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    show_default=True,
    help="Preview pipeline execution without writing artefacts.",
)
@click.pass_context
def router_pipeline_run(
    ctx: click.Context,
    case_id: str | None,
    with_capture: bool,
    param: tuple[str, ...],
    dry_run: bool,
) -> None:
    """Execute the guarded router forensic pipeline."""

    case = _resolve_router_case(ctx, "router pipeline run", case_id)
    if case is None:
        return

    params = _collect_router_params(
        ctx,
        "router pipeline run",
        case=case,
        dry_run=dry_run,
        extra={"with_capture": with_capture},
        param=param,
    )
    if params is None:
        return

    result = router_pipeline.run_pipeline(params)
    _router_emit(ctx, "router pipeline run", result)


@router.command("summarize")
@click.option(
    "--case",
    "case_id",
    default=None,
    help="Optional case identifier for summary generation",
)
@click.option(
    "--param",
    "param",
    multiple=True,
    type=str,
    help="Summary parameter override (key=value).",
)
@click.option(
    "--dry-run/--no-dry-run",
    default=True,
    show_default=True,
    help="Preview summary output without writing files.",
)
@click.pass_context
def router_summarize_cmd(
    ctx: click.Context,
    case_id: str | None,
    param: tuple[str, ...],
    dry_run: bool,
) -> None:
    """Summarise router analysis findings."""

    case = _resolve_router_case(ctx, "router summarize", case_id)
    if case is None:
        return

    params = _collect_router_params(
        ctx,
        "router summarize",
        case=case,
        dry_run=dry_run,
        param=param,
    )
    if params is None:
        return

    result = router_summary.summarize(params)
    _router_emit(ctx, "router summarize", result)


def _ensure_legacy_enabled(ctx: click.Context) -> None:
    if not ctx.obj.get("legacy_enabled"):
        message = "Legacy wrappers are disabled. Re-run with --legacy to access deprecated tools."
        _emit_status(
            ctx,
            "legacy",
            status="error",
            message=message,
            errors=[message],
            exit_code=1,
        )


def _run_legacy_script(script_name: str, args: tuple[str, ...]) -> int:
    script_path = Path(__file__).resolve().parent.parent / "scripts" / script_name
    if not script_path.exists():
        click.echo(
            f"Legacy script '{script_name}' is not packaged. See LEGACY.md for migration guidance.",
            err=True,
        )
        return 1

    result = subprocess.run([str(script_path), *args], check=False)
    return result.returncode


@cli.group()
@click.pass_context
def legacy(ctx: click.Context) -> None:
    """Access deprecated shell script wrappers."""

    _ensure_legacy_enabled(ctx)


@legacy.command("ioc-grep")
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def legacy_ioc_grep(args: tuple[str, ...]) -> None:
    """Invoke the legacy IoC grep script."""

    exit_code = _run_legacy_script("ioc_grep.sh", args)
    if exit_code:
        sys.exit(exit_code)


@legacy.command("quick-triage")
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def legacy_quick_triage(args: tuple[str, ...]) -> None:
    """Invoke the legacy quick triage script."""

    exit_code = _run_legacy_script("quick-triage.sh", args)
    if exit_code:
        sys.exit(exit_code)


def main() -> None:
    """Entry point for console scripts."""

    cli(prog_name="forensic-cli")


if __name__ == "__main__":  # pragma: no cover - manual execution
    main()
