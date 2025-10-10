"""Guarded Codex helpers wrapping legacy shell scripts."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Default locations mirror the legacy bash scripts but allow callers to
# override them explicitly. The paths intentionally remain relative to a
# guarded USB workspace so that dry-run previews can communicate provenance.
DEFAULT_WORKSPACE = Path("/mnt/usb_rw")
LOG_DIR_NAME = "codex_logs"
CODEX_HOME_NAME = "codex_home"
META_FILE_NAME = "meta.jsonl"
INSTALL_LOG_NAME = "install.log"
CONTROL_LOG_NAME = "kali_server_control.log"
PID_FILE_NAME = "mcp.pid"


@dataclass(slots=True)
class CodexActionResult:
    """Container describing the outcome of a Codex helper action."""

    status: str
    message: str
    data: dict[str, Any]
    details: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _repository_root() -> Path:
    """Return the repository root based on this module location."""

    # ``parents[2]`` resolves ``/path/to/repo`` from
    # ``/path/to/repo/forensic/codex/__init__.py``.
    return Path(__file__).resolve().parents[2]


from . import installer as _installer  # noqa: E402  - re-export after helpers
from . import runner as _runner  # noqa: E402

install = _installer.install
start = _runner.start
stop = _runner.stop
status = _runner.status

__all__ = [
    "CodexActionResult",
    "DEFAULT_WORKSPACE",
    "LOG_DIR_NAME",
    "CODEX_HOME_NAME",
    "META_FILE_NAME",
    "INSTALL_LOG_NAME",
    "CONTROL_LOG_NAME",
    "PID_FILE_NAME",
    "install",
    "start",
    "stop",
    "status",
]
