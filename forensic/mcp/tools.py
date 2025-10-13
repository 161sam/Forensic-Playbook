"""Adapters that expose Forensic Playbook functionality as MCP tools."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..core.framework import ForensicFramework
from ..modules.reporting.generator import ReportGenerator
from ..modules.router import capture as router_capture
from ..modules.router import env as router_env
from ..modules.router import extract as router_extract
from ..modules.router import manifest as router_manifest
from ..modules.router import pipeline as router_pipeline
from ..modules.router import summarize as router_summarize
from ..modules.router.common import RouterResult
from .schemas import MCPToolArgument, MCPToolDescriptor

PROMPT_RESOURCE = "forensic/mcp/prompts/forensic_mode.txt"
PROMPT_PATH = Path(__file__).with_name("prompts") / "forensic_mode.txt"


def _to_serialisable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: _to_serialisable(val) for key, val in value.items()}
    if isinstance(value, list | tuple | set):
        return [_to_serialisable(item) for item in value]
    return value


@dataclass(slots=True)
class ToolArgument:
    """Description of a tool argument."""

    name: str
    description: str
    required: bool = False
    arg_type: str = "string"

    def to_schema(self) -> MCPToolArgument:
        return {
            "name": self.name,
            "description": self.description,
            "required": self.required,
            "type": self.arg_type,
        }


@dataclass(slots=True)
class ToolExecutionResult:
    """Result returned by tool handlers."""

    status: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "status": self.status,
            "message": self.message,
            "data": _to_serialisable(self.data),
        }
        if self.warnings:
            payload["warnings"] = list(self.warnings)
        if self.errors:
            payload["errors"] = list(self.errors)
        return payload


@dataclass(slots=True)
class MCPTool:
    """Internal representation of an MCP tool."""

    name: str
    description: str
    handler: Callable[[ForensicFramework, Dict[str, Any]], ToolExecutionResult]
    arguments: List[ToolArgument] = field(default_factory=list)
    returns: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_descriptor(self) -> MCPToolDescriptor:
        descriptor: MCPToolDescriptor = {
            "name": self.name,
            "description": self.description,
            "arguments": [argument.to_schema() for argument in self.arguments],
        }
        if self.returns:
            descriptor["returns"] = self.returns
        if self.metadata:
            descriptor["metadata"] = _to_serialisable(self.metadata)
        return descriptor


def _module_result_to_dict(result: Any) -> Dict[str, Any]:
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


def _case_to_dict(case: Any) -> Dict[str, Any]:
    return {
        "case_id": getattr(case, "case_id", ""),
        "name": getattr(case, "name", ""),
        "description": getattr(case, "description", ""),
        "investigator": getattr(case, "investigator", ""),
        "created_at": getattr(case, "created_at", ""),
        "case_dir": str(getattr(case, "case_dir", "") or ""),
        "metadata": dict(getattr(case, "metadata", {}) or {}),
    }


def _normalise_params(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return {}
        try:
            loaded = json.loads(stripped)
            if isinstance(loaded, dict):
                return loaded
        except json.JSONDecodeError:
            pass
        return {"value": stripped}
    return {"value": value}


def _module_status_to_result(status: str) -> str:
    normalized = status.lower()
    if normalized == "success":
        return "success"
    if normalized in {"partial", "skipped"}:
        return "warning"
    return "error"


def _router_status_to_result(status: str) -> str:
    normalized = status.lower()
    if normalized in {"success", "completed", "ok"}:
        return "success"
    if normalized in {"partial", "skipped", "warning"}:
        return "warning"
    return "error"


def _router_result_to_tool_result(
    action: str, result: RouterResult
) -> ToolExecutionResult:
    data: Dict[str, Any] = {
        "timestamp": result.timestamp,
        "details": list(result.details),
    }
    if result.data:
        data["payload"] = dict(result.data)
    if result.artifacts:
        data["artifacts"] = [dict(item) for item in result.artifacts]

    return ToolExecutionResult(
        status=_router_status_to_result(result.status),
        message=result.message or action,
        data=data,
        errors=list(result.errors),
    )


def _diagnostics_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    cases = framework.list_cases()
    modules = sorted(framework.list_modules())
    data = {
        "workspace": str(framework.workspace),
        "cases": cases,
        "modules": modules,
    }
    return ToolExecutionResult(
        status="success",
        message="Diagnostics completed",
        data=data,
    )


def _cases_list_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    cases = framework.list_cases()
    return ToolExecutionResult(
        status="success",
        message=f"Retrieved {len(cases)} case(s)",
        data={"cases": cases},
    )


def _cases_create_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    name = arguments.get("name")
    investigator = arguments.get("investigator")
    description = arguments.get("description", "")
    case_id = arguments.get("case_id")

    missing: List[str] = []
    if not name:
        missing.append("name")
    if not investigator:
        missing.append("investigator")
    if missing:
        return ToolExecutionResult(
            status="error",
            message="Missing required arguments",
            errors=[f"Missing argument: {item}" for item in missing],
        )

    case = framework.create_case(
        name=name,
        description=description,
        investigator=investigator,
        case_id=case_id,
    )

    return ToolExecutionResult(
        status="success",
        message=f"Case created: {case.case_id}",
        data={"case": _case_to_dict(case)},
    )


def _modules_list_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    modules = sorted(framework.list_modules())
    return ToolExecutionResult(
        status="success",
        message=f"{len(modules)} module(s) registered",
        data={"modules": modules},
    )


def _modules_run_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    module_name = arguments.get("module_name")
    case_id = arguments.get("case_id")
    params = _normalise_params(arguments.get("params"))

    if not module_name or not case_id:
        return ToolExecutionResult(
            status="error",
            message="module_name and case_id are required",
            errors=["module_name and case_id are required"],
        )

    try:
        framework.load_case(case_id)
    except ValueError as exc:
        return ToolExecutionResult(
            status="error",
            message=str(exc),
            errors=[str(exc)],
        )

    try:
        result = framework.execute_module(module_name, params=params)
    except Exception as exc:  # pragma: no cover - execution errors vary per module
        return ToolExecutionResult(
            status="error",
            message=f"Module execution failed: {exc}",
            errors=[str(exc)],
        )

    payload = _module_result_to_dict(result)
    status = _module_status_to_result(payload["status"])
    message = f"Module execution status: {payload['status']}"
    warnings: List[str] = []
    errors: List[str] = []
    if payload.get("errors"):
        if status == "error":
            errors = list(payload["errors"])
        elif status == "warning":
            warnings = list(payload["errors"])

    return ToolExecutionResult(
        status=status,
        message=message,
        data={
            "case_id": case_id,
            "module_name": module_name,
            "result": payload,
        },
        warnings=warnings,
        errors=errors,
    )


def _reports_generate_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    case_id = arguments.get("case_id")
    if not case_id:
        return ToolExecutionResult(
            status="error",
            message="case_id is required",
            errors=["case_id is required"],
        )

    fmt = arguments.get("format", "html")
    output_file = arguments.get("output_file")
    dry_run = bool(arguments.get("dry_run", False))

    try:
        case = framework.load_case(case_id)
    except ValueError as exc:
        return ToolExecutionResult(
            status="error",
            message=str(exc),
            errors=[str(exc)],
        )

    params: Dict[str, Any] = {"format": fmt}
    if output_file:
        params["output_file"] = output_file
    if dry_run:
        params["dry_run"] = True

    module = ReportGenerator(case_dir=case.case_dir, config=framework.config)
    result = module.run(None, params)
    payload = _module_result_to_dict(result)
    status = _module_status_to_result(payload["status"])
    message = f"Report generation status: {payload['status']}"
    warnings: List[str] = []
    if payload.get("errors"):
        warnings.extend(payload["errors"])

    return ToolExecutionResult(
        status=status,
        message=message,
        data={
            "case_id": case.case_id,
            "params": params,
            "result": payload,
        },
        warnings=warnings,
    )


def _router_env_init_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    params = dict(arguments)
    params.setdefault("root", str(framework.workspace / "router"))
    result = router_env.init_environment(params)
    return _router_result_to_tool_result("Router environment initialisation", result)


def _router_capture_setup_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    params = dict(arguments)
    base = framework.workspace / "router"
    params.setdefault("pcap_dir", str(base / "capture"))
    params.setdefault("meta_dir", str(base / "capture" / "meta"))
    result = router_capture.setup(params)
    return _router_result_to_tool_result("Router capture setup", result)


def _router_capture_start_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    params = dict(arguments)
    base = framework.workspace / "router"
    params.setdefault("pcap_dir", str(base / "capture"))
    params.setdefault("meta_dir", str(base / "capture" / "meta"))
    result = router_capture.start(params)
    return _router_result_to_tool_result("Router capture start", result)


def _router_capture_stop_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    params = dict(arguments)
    result = router_capture.stop(params)
    return _router_result_to_tool_result("Router capture stop", result)


def _router_extract_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    params = dict(arguments)
    kind = params.pop("kind", None)
    if not kind:
        return ToolExecutionResult(
            status="error",
            message="Missing router extract kind",
            errors=["Argument 'kind' is required"],
        )
    result = router_extract.extract(str(kind), params)
    return _router_result_to_tool_result(f"Router extract {kind}", result)


def _router_manifest_write_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    params = dict(arguments)
    result = router_manifest.write_manifest(params)
    return _router_result_to_tool_result("Router manifest write", result)


def _router_pipeline_run_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    params = dict(arguments)
    result = router_pipeline.run_pipeline(params)
    return _router_result_to_tool_result("Router pipeline run", result)


def _router_summarize_handler(
    framework: ForensicFramework, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    params = dict(arguments)
    result = router_summarize.summarize(params)
    return _router_result_to_tool_result("Router summarize", result)


def get_tool_catalog(framework: ForensicFramework) -> List[MCPTool]:
    """Return the list of available MCP tools."""

    return [
        MCPTool(
            name="diagnostics.ping",
            description="Return workspace, case and module information",
            handler=_diagnostics_handler,
        ),
        MCPTool(
            name="cases.list",
            description="List all cases stored in the workspace",
            handler=_cases_list_handler,
        ),
        MCPTool(
            name="cases.create",
            description="Create a new forensic case",
            handler=_cases_create_handler,
            arguments=[
                ToolArgument("name", "Human readable case name", required=True),
                ToolArgument("investigator", "Investigator responsible", required=True),
                ToolArgument("description", "Optional case description"),
                ToolArgument("case_id", "Optional explicit case identifier"),
            ],
        ),
        MCPTool(
            name="modules.list",
            description="List registered modules",
            handler=_modules_list_handler,
        ),
        MCPTool(
            name="modules.run",
            description="Execute a registered module for a case",
            handler=_modules_run_handler,
            arguments=[
                ToolArgument("case_id", "Case identifier", required=True),
                ToolArgument("module_name", "Module name to execute", required=True),
                ToolArgument(
                    "params",
                    "JSON encoded parameters passed to the module",
                    required=False,
                ),
            ],
            returns="Module execution result",
        ),
        MCPTool(
            name="reports.generate",
            description="Generate a case report using built-in reporting module",
            handler=_reports_generate_handler,
            arguments=[
                ToolArgument("case_id", "Case identifier", required=True),
                ToolArgument(
                    "format",
                    "Report format (html, pdf, json, md)",
                    required=False,
                ),
                ToolArgument(
                    "output_file",
                    "Optional output file name (relative to case)",
                    required=False,
                ),
                ToolArgument("dry_run", "If true, only plan the report"),
            ],
            returns="Report generation metadata",
        ),
        MCPTool(
            name="router.env.init",
            description="Initialise the guarded router workspace layout",
            handler=_router_env_init_handler,
            arguments=[
                ToolArgument(
                    "root",
                    "Router workspace root (defaults to <workspace>/router)",
                    required=False,
                ),
                ToolArgument("dry_run", "Preview actions without modifying files"),
                ToolArgument("legacy", "Invoke legacy prepare_env.sh wrapper"),
            ],
        ),
        MCPTool(
            name="router.capture.setup",
            description="Prepare directories required for passive router capture",
            handler=_router_capture_setup_handler,
            arguments=[
                ToolArgument("pcap_dir", "Directory for capture PCAP files"),
                ToolArgument("meta_dir", "Directory for capture metadata"),
                ToolArgument("dry_run", "Preview without creating directories"),
                ToolArgument("legacy", "Invoke legacy tcpdump_setup.sh"),
            ],
        ),
        MCPTool(
            name="router.capture.start",
            description="Start a guarded router capture (disabled unless enable_live_capture is true)",
            handler=_router_capture_start_handler,
            arguments=[
                ToolArgument("interface", "Network interface to monitor"),
                ToolArgument("duration", "Capture duration in seconds"),
                ToolArgument("bpf", "Optional BPF filter"),
                ToolArgument("pcap_dir", "Directory for capture PCAP files"),
                ToolArgument("meta_dir", "Directory for capture metadata"),
                ToolArgument("tool", "Capture binary to use (default tcpdump)"),
                ToolArgument(
                    "enable_live_capture",
                    "Must be true to perform a real capture; otherwise guard message",
                ),
                ToolArgument("dry_run", "Preview capture command only"),
                ToolArgument("legacy", "Invoke legacy tcpdump_passive_capture.sh"),
            ],
        ),
        MCPTool(
            name="router.capture.stop",
            description="Provide guarded guidance for stopping router captures",
            handler=_router_capture_stop_handler,
            arguments=[
                ToolArgument(
                    "dry_run", "Show stop guidance without terminating processes"
                ),
                ToolArgument("legacy", "Invoke legacy tcpdump_passive_stop.sh"),
            ],
        ),
        MCPTool(
            name="router.extract",
            description="Extract router artefacts of a specific kind",
            handler=_router_extract_handler,
            arguments=[
                ToolArgument(
                    "kind", "Extraction kind (ui, ddns, devices, ...)", required=True
                ),
                ToolArgument(
                    "input",
                    "Source directory containing raw router data",
                    required=True,
                ),
                ToolArgument("out", "Destination directory for extracted artefacts"),
                ToolArgument("dry_run", "Preview extraction without writing output"),
                ToolArgument("legacy", "Invoke matching legacy extraction script"),
            ],
        ),
        MCPTool(
            name="router.manifest.write",
            description="Generate a deterministic manifest for router artefacts",
            handler=_router_manifest_write_handler,
            arguments=[
                ToolArgument("out", "Manifest file to create", required=True),
                ToolArgument("source", "Source directory to catalogue"),
                ToolArgument("dry_run", "Preview manifest generation"),
                ToolArgument("legacy", "Invoke legacy manifest script"),
            ],
        ),
        MCPTool(
            name="router.pipeline.run",
            description="Execute the router forensic pipeline (dry-run by default)",
            handler=_router_pipeline_run_handler,
            arguments=[
                ToolArgument("plan", "Optional YAML pipeline description"),
                ToolArgument("dry_run", "Preview pipeline steps without executing"),
                ToolArgument("legacy", "Invoke legacy run_forensic_pipeline.sh"),
            ],
        ),
        MCPTool(
            name="router.summarize",
            description="Summarise router analysis findings",
            handler=_router_summarize_handler,
            arguments=[
                ToolArgument(
                    "in", "Directory containing analysis artefacts", required=True
                ),
                ToolArgument("out", "Summary file to generate", required=True),
                ToolArgument("dry_run", "Preview summary generation"),
                ToolArgument("legacy", "Invoke legacy summarize_report.sh"),
            ],
        ),
    ]


def build_expose_payload(framework: ForensicFramework) -> Dict[str, Any]:
    """Construct the payload exposed via ``forensic-cli mcp expose``."""

    tools = sorted(get_tool_catalog(framework), key=lambda tool: tool.name)
    descriptors = [tool.to_descriptor() for tool in tools]
    payload: Dict[str, Any] = {
        "version": "1.0",
        "prompt": {
            "name": "forensic_mode",
            "resource": PROMPT_RESOURCE,
            "path": str(PROMPT_PATH.resolve()),
        },
        "tools": descriptors,
        "metadata": {
            "modules": len(framework.list_modules()),
            "cases": len(framework.list_cases()),
        },
    }
    return payload


def run_tool(
    framework: ForensicFramework, tool_name: str, arguments: Dict[str, Any]
) -> ToolExecutionResult:
    """Execute a tool locally via the MCP adapter."""

    catalog = {tool.name: tool for tool in get_tool_catalog(framework)}
    tool = catalog.get(tool_name)
    if not tool:
        return ToolExecutionResult(
            status="error",
            message=f"Unknown tool: {tool_name}",
            errors=[f"Tool '{tool_name}' is not registered"],
        )

    return tool.handler(framework, arguments)
