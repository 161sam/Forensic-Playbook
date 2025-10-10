"""Adapters that expose Forensic Playbook functionality as MCP tools."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..core.framework import ForensicFramework
from ..modules.reporting.generator import ReportGenerator

from .schemas import MCPToolArgument, MCPToolDescriptor

PROMPT_RESOURCE = "forensic/mcp/prompts/forensic_mode.txt"
PROMPT_PATH = Path(__file__).with_name("prompts") / "forensic_mode.txt"


def _to_serialisable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: _to_serialisable(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
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
