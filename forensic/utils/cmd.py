"""Utilities for executing external commands with guards."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Optional


class CommandError(RuntimeError):
    """Raised when an external command fails."""


def which(tool: str) -> Optional[str]:
    """Return the full path of ``tool`` if available."""

    return shutil.which(tool)


def ensure_tool(tool: str) -> str:
    """Ensure that ``tool`` exists on PATH and return its absolute path."""

    resolved = which(tool)
    if not resolved:
        raise CommandError(f"Required tool not found: {tool}")
    return resolved


def run(
    cmd: Iterable[str], *, cwd: Optional[Path] = None, timeout: int = 300
) -> subprocess.CompletedProcess:
    """Execute ``cmd`` and return the completed process."""

    try:
        return subprocess.run(
            list(cmd),
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
    except subprocess.CalledProcessError as exc:  # pragma: no cover - passthrough
        raise CommandError(
            f"Command failed ({exc.returncode}): {' '.join(exc.cmd)}"
        ) from exc


__all__ = ["CommandError", "ensure_tool", "run", "which"]
