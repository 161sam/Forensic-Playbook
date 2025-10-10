"""Forensic Playbook package initialization and SDK exports."""

from importlib.metadata import PackageNotFoundError, version

from .codex import (
    install as install_codex_environment,
)
from .codex import (
    start as start_codex_server,
)
from .codex import (
    status as get_codex_status,
)
from .codex import (
    stop as stop_codex_server,
)
from .core.framework import ForensicFramework
from .core.module import ForensicModule
from .mcp import MCPClient, MCPConfig, ToolExecutionResult
from .mcp import build_expose_payload as build_mcp_tool_payload
from .mcp import run_tool as run_mcp_tool

__all__ = [
    "__version__",
    "ForensicFramework",
    "ForensicModule",
    "MCPClient",
    "MCPConfig",
    "ToolExecutionResult",
    "build_mcp_tool_payload",
    "run_mcp_tool",
    "install_codex_environment",
    "start_codex_server",
    "stop_codex_server",
    "get_codex_status",
]

try:  # pragma: no cover - depends on package metadata
    __version__ = version("forensic-playbook")
except PackageNotFoundError:  # pragma: no cover - local development fallback
    __version__ = "0.2.0-dev"
