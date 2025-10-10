"""MCP client, configuration helpers and tool adapters for Forensic Playbook."""

from .adapters import ToolExecutionResult, iter_tool_names, resolve
from .adapters import run as run_tool
from .client import MCPClient
from .config import MCPConfig
from .registry import build_catalog
from .schemas import MCPExposePayload, MCPToolArgument, MCPToolDescriptor
from .servers import ServerStatus, list_statuses, summarise
from .tools import PROMPT_PATH, PROMPT_RESOURCE, get_tool_catalog


def build_expose_payload(framework):  # type: ignore[no-untyped-def]
    """Backward compatible alias returning the MCP tool catalogue."""

    return build_catalog(framework)


__all__ = [
    "MCPClient",
    "MCPConfig",
    "MCPExposePayload",
    "MCPToolArgument",
    "MCPToolDescriptor",
    "PROMPT_PATH",
    "PROMPT_RESOURCE",
    "ToolExecutionResult",
    "build_catalog",
    "build_expose_payload",
    "get_tool_catalog",
    "iter_tool_names",
    "list_statuses",
    "resolve",
    "run_tool",
    "ServerStatus",
    "summarise",
]
