"""Command line interface for the Forensic Playbook framework."""

from __future__ import annotations

import importlib
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import click

from .core.evidence import EvidenceType
from .core.framework import ForensicFramework
from .modules.acquisition.disk_imaging import DiskImagingModule
from .modules.acquisition.live_response import LiveResponseModule
from .modules.acquisition.memory_dump import MemoryDumpModule
from .modules.acquisition.network_capture import NetworkCaptureModule
from .modules.analysis.filesystem import FilesystemAnalysisModule
from .modules.analysis.malware import MalwareAnalysisModule
from .modules.analysis.timeline import TimelineModule
from .modules.reporting.exporter import get_pdf_renderer
from .modules.reporting.generator import ReportGenerator
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
    legacy: bool,
) -> None:
    """Forensic Framework CLI."""

    ctx.ensure_object(dict)

    workspace_path = Path(workspace) if workspace else None
    config_path = Path(config) if config else None

    ctx.obj["framework"] = ForensicFramework(
        config_file=config_path, workspace=workspace_path
    )
    ctx.obj["verbose"] = verbose
    ctx.obj["skipped_modules"] = {}
    ctx.obj["legacy_enabled"] = legacy

    _register_default_modules(ctx)


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

    click.echo(f"✓ Case created: {case.case_id}")
    click.echo(f"  Name: {case.name}")
    click.echo(f"  Directory: {case.case_dir}")


@case.command("list")
@click.pass_context
def list_cases(ctx: click.Context) -> None:
    """List all cases."""

    framework: ForensicFramework = ctx.obj["framework"]
    cases = framework.list_cases()

    if not cases:
        click.echo("No cases found")
        return

    click.echo("\nCases:")
    for case in cases:
        click.echo(f"  {case['case_id']}: {case['name']}")
        click.echo(f"    Investigator: {case['investigator']}")
        click.echo(f"    Created: {case['created_at']}")
        click.echo()


@case.command("load")
@click.argument("case_id")
@click.pass_context
def load_case(ctx: click.Context, case_id: str) -> None:
    """Load an existing case."""

    framework: ForensicFramework = ctx.obj["framework"]

    try:
        case = framework.load_case(case_id)
        click.echo(f"✓ Case loaded: {case.case_id}")
        click.echo(f"  Name: {case.name}")
        click.echo(f"  Directory: {case.case_dir}")
    except ValueError as exc:
        click.echo(f"✗ Error: {exc}", err=True)
        sys.exit(1)


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
        click.echo("✗ No active case. Load or create a case first.", err=True)
        sys.exit(1)

    evidence_type_enum = EvidenceType[evidence_type.upper()]

    evidence = framework.add_evidence(
        evidence_type=evidence_type_enum,
        source_path=Path(source_path),
        description=description,
    )

    click.echo(f"✓ Evidence added: {evidence.evidence_id}")
    click.echo(f"  Type: {evidence.evidence_type.value}")
    click.echo(f"  Hash: {evidence.hash_sha256}")


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

    click.echo("Available modules:")
    for module_name in available:
        click.echo(f"  • {module_name}")

    if skipped:
        click.echo("\nUnavailable modules:")
        for module_name, reason in skipped.items():
            click.echo(f"  • {module_name} ({reason})")


@modules.command("run")
@click.argument("module_name")
@click.option("--param", multiple=True, type=str, help="Module parameter key=value")
@click.pass_context
def run_module(ctx: click.Context, module_name: str, param: tuple[str, ...]) -> None:
    """Run a module with optional parameters."""

    framework: ForensicFramework = ctx.obj["framework"]
    params: Dict[str, str] = {}

    for item in param:
        if "=" not in item:
            click.echo(
                f"✗ Invalid parameter '{item}'. Use key=value format.",
                err=True,
            )
            sys.exit(1)
        key, value = item.split("=", 1)
        params[key] = value

    try:
        result = framework.run_module(module_name, None, params)
    except KeyError:
        click.echo(f"✗ Unknown module: {module_name}", err=True)
        sys.exit(1)

    click.echo(f"Module {module_name} executed with status: {result.status}")
    if result.findings:
        click.echo("Findings:")
        for finding in result.findings:
            click.echo(f"  - {finding.get('description', finding)}")

    if result.errors:
        click.echo("Errors:")
        for error in result.errors:
            click.echo(f"  - {error}")


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
    "--out", "out_path", type=click.Path(), default=None, help="Output file path"
)
@click.option("--case", "case_id", required=True, help="Case identifier")
@click.option(
    "--dry-run", is_flag=True, help="Prepare report data without writing files"
)
@click.pass_context
def generate_report(
    ctx: click.Context,
    fmt: str,
    out_path: str | None,
    case_id: str,
    dry_run: bool,
) -> None:
    """Generate a case report using the reporting module."""

    framework: ForensicFramework = ctx.obj["framework"]

    try:
        case = framework.load_case(case_id)
    except ValueError as exc:
        click.echo(f"✗ Error: {exc}", err=True)
        sys.exit(1)

    params = {"format": fmt}
    if out_path:
        params["output_file"] = out_path
    if dry_run:
        params["dry_run"] = True

    module = ReportGenerator(case_dir=case.case_dir, config=framework.config)
    result = module.run(None, params)

    click.echo(f"Report generation status: {result.status}")
    if result.output_path:
        click.echo(f"Output file: {result.output_path}")
    if result.metadata.get("dry_run"):
        click.echo("Dry-run mode: no files were written.")
    if result.errors:
        click.echo("Errors:")
        for error in result.errors:
            click.echo(f"  - {error}")
    for finding in result.findings:
        description = finding.get("description")
        if description:
            click.echo(f"Finding: {description}")


@cli.command()
@click.pass_context
def diagnostics(ctx: click.Context) -> None:
    """Display environment diagnostics and guard information."""

    framework: ForensicFramework = ctx.obj["framework"]
    workspace = framework.workspace

    click.echo("=== Environment diagnostics ===")
    click.echo(f"Timezone: {datetime.now().astimezone().tzinfo}")
    click.echo(f"Workspace: {workspace}")

    paths_to_check = [workspace, workspace / "analysis", workspace / "reports"]
    click.echo("\nWrite permissions:")
    for path in paths_to_check:
        exists = path.exists()
        writable = os.access(path if exists else path.parent, os.W_OK)
        status = "✓" if writable else "✗"
        click.echo(f"  {status} {path} ({'exists' if exists else 'will be created'})")

    tool_groups = {
        "Network capture": ["tcpdump", "dumpcap"],
        "Timeline tooling": ["log2timeline.py", "mactime"],
        "Sleuthkit": ["fls"],
        "Memory acquisition": ["avml", "lime", "winpmem"],
        "YARA": ["yara"],
    }

    click.echo("\nTool availability:")
    for label, tools in tool_groups.items():
        available = [tool for tool in tools if shutil.which(tool)]
        missing = [tool for tool in tools if tool not in available]
        parts = []
        if available:
            parts.append(f"available: {', '.join(sorted(available))}")
        if missing:
            parts.append(f"missing: {', '.join(sorted(missing))}")
        message = "; ".join(parts) if parts else "no tools detected"
        click.echo(f"  - {label}: {message}")

    optional_packages = {
        "volatility3": "volatility3",
        "pyshark": "pyshark",
        "yara-python": "yara",
    }

    click.echo("\nPython packages:")
    for label, module_name in optional_packages.items():
        try:
            importlib.import_module(module_name)
            status = "available"
        except ModuleNotFoundError:
            status = "missing"
        click.echo(f"  - {label}: {status}")

    click.echo("\nDiagnostics complete.")


def _ensure_legacy_enabled(ctx: click.Context) -> None:
    if not ctx.obj.get("legacy_enabled"):
        click.echo(
            "Legacy wrappers are disabled. Re-run with --legacy to access deprecated tools.",
            err=True,
        )
        ctx.exit(1)


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
