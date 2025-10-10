"""MCP client, configuration helpers and tool adapters for Forensic Playbook."""

from .client import MCPClient
from .config import MCPConfig
from .schemas import MCPExposePayload, MCPToolArgument, MCPToolDescriptor
from .tools import (
    PROMPT_PATH,
    PROMPT_RESOURCE,
    ToolExecutionResult,
    build_expose_payload,
    get_tool_catalog,
    run_tool,
)

__all__ = [
    "MCPClient",
    "MCPConfig",
    "MCPExposePayload",
    "MCPToolArgument",
    "MCPToolDescriptor",
    "PROMPT_PATH",
    "PROMPT_RESOURCE",
    "ToolExecutionResult",
    "build_expose_payload",
    "get_tool_catalog",
    "run_tool",
]
