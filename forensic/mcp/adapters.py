"""Adapters mapping MCP tool names to framework entry points."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping

from ..core.framework import ForensicFramework
from .tools import (
    ToolExecutionResult,
    get_tool_catalog,
    run_tool as _legacy_run_tool,
)


@dataclass(slots=True)
class AdapterInvocation:
    """Description of a tool invocation resolved by the adapter."""

    name: str
    arguments: Dict[str, Any]
    local: bool
    dry_run: bool


def _normalise_arguments(arguments: Mapping[str, Any] | None, *, dry_run: bool) -> Dict[str, Any]:
    normalised: Dict[str, Any] = {k: v for k, v in (arguments or {}).items()}
    normalised.setdefault("dry_run", dry_run)
    return normalised


def _clone_result(result: ToolExecutionResult, *, data: Dict[str, Any] | None = None) -> ToolExecutionResult:
    payload = data if data is not None else dict(result.data)
    return ToolExecutionResult(
        status=result.status,
        message=result.message,
        data=payload,
        warnings=list(result.warnings),
        errors=list(result.errors),
    )


def iter_tool_names(framework: ForensicFramework) -> Iterable[str]:
    """Yield the registered tool names in sorted order."""

    yield from sorted(tool.name for tool in get_tool_catalog(framework))


def resolve(
    framework: ForensicFramework,
    tool_name: str,
    arguments: Mapping[str, Any] | None = None,
    *,
    local: bool = False,
    dry_run: bool = True,
) -> AdapterInvocation:
    """Return a normalised invocation for ``tool_name``.

    This helper prepares argument mappings and notes whether execution happens
    locally or is routed to a remote MCP server.
    """

    return AdapterInvocation(
        name=tool_name,
        arguments=_normalise_arguments(arguments, dry_run=dry_run),
        local=local,
        dry_run=dry_run,
    )


def run(
    framework: ForensicFramework,
    tool_name: str,
    arguments: Mapping[str, Any] | None = None,
    *,
    local: bool = False,
    dry_run: bool = True,
) -> ToolExecutionResult:
    """Execute ``tool_name`` via the MCP adapter layer.

    Parameters
    ----------
    framework:
        Active :class:`~forensic.core.framework.ForensicFramework` instance.
    tool_name:
        Fully qualified tool identifier (``diagnostics.ping``, ``modules.run`` …).
    arguments:
        Mapping of arguments provided by the caller. Values remain untouched
        except for the addition of the ``dry_run`` flag when missing.
    local:
        When ``True`` the adapter performs a direct in-process call. When
        ``False`` a guarded warning result is returned (remote execution will be
        implemented by dedicated MCP connectors).
    dry_run:
        Defaults to ``True`` in line with Forensic Mode guard rails.
    """

    invocation = resolve(
        framework,
        tool_name,
        arguments,
        local=local,
        dry_run=dry_run,
    )

    if not invocation.local:
        return ToolExecutionResult(
            status="warning",
            message="Remote MCP execution is not yet available",
            data={
                "tool": tool_name,
                "arguments": dict(invocation.arguments),
                "local": False,
            },
            warnings=["Use --local to execute via in-process adapters."],
        )

    legacy_result = _legacy_run_tool(framework, tool_name, invocation.arguments)
    payload = dict(legacy_result.data)
    payload.setdefault("arguments", dict(invocation.arguments))
    payload.setdefault("tool", tool_name)
    payload.setdefault("ok", legacy_result.status == "success")
    payload["dry_run"] = invocation.arguments.get("dry_run", dry_run)

    return _clone_result(legacy_result, data=payload)
