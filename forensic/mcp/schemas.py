"""Typed schemas used by the MCP integration layer."""

from __future__ import annotations

from typing import Any, Dict, List, NotRequired, Optional, TypedDict


class MCPToolArgument(TypedDict):
    """Describe an argument accepted by an MCP tool."""

    name: str
    type: str
    required: bool
    description: str


class MCPToolDescriptor(TypedDict):
    """Descriptor for a tool exposed to Codex via MCP."""

    name: str
    description: str
    arguments: List[MCPToolArgument]
    returns: NotRequired[str]
    metadata: NotRequired[Dict[str, Any]]


class MCPExposePayload(TypedDict):
    """Structure emitted by ``forensic-cli mcp expose``."""

    version: str
    prompt: Dict[str, str]
    tools: List[MCPToolDescriptor]
    metadata: NotRequired[Dict[str, Any]]


class MCPToolRunRequest(TypedDict):
    """Payload for running an MCP tool via HTTP."""

    tool: str
    arguments: Dict[str, Any]


class MCPToolRunResponse(TypedDict, total=False):
    """Expected structure returned by MCP server."""

    status: str
    message: str
    data: Dict[str, Any]
    warnings: List[str]
    errors: List[str]
    details: Optional[List[str]]
