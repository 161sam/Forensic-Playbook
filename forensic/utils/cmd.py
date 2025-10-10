"""Utilities for executing external commands with guards."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence

Command = Sequence[str | Path]


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


def _normalise_command(cmd: Iterable[str | Path]) -> list[str]:
    if isinstance(cmd, str | bytes):
        raise TypeError(
            "Command must be an iterable of path/str components, not a string"
        )

    normalised: list[str] = []
    for part in cmd:
        if isinstance(part, Path):
            normalised.append(str(part))
        elif isinstance(part, str | bytes):
            normalised.append(str(part))
        else:
            raise TypeError(f"Unsupported command argument type: {type(part)!r}")

    if not normalised:
        raise ValueError("Command must contain at least one argument")

    return normalised


def run(
    cmd: Command,
    *,
    cwd: Optional[Path] = None,
    timeout: int = 300,
    env: Optional[Mapping[str, str]] = None,
) -> subprocess.CompletedProcess:
    """Execute ``cmd`` safely and return the completed process."""

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    command = _normalise_command(cmd)

    try:
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env is not None else None,
        )
    except subprocess.TimeoutExpired as exc:
        quoted = " ".join(shlex.quote(arg) for arg in command)
        raise CommandError(f"Command timed out after {timeout}s: {quoted}") from exc
    except subprocess.CalledProcessError as exc:
        quoted = " ".join(shlex.quote(arg) for arg in exc.cmd)
        raise CommandError(f"Command failed ({exc.returncode}): {quoted}") from exc


def run_cmd(
    cmd: Command,
    *,
    cwd: Optional[Path] = None,
    timeout: int = 300,
    env: Optional[Mapping[str, str]] = None,
    check: bool = False,
    capture_output: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """Execute ``cmd`` safely and return the completed process."""

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    command = _normalise_command(cmd)

    try:
        return subprocess.run(
            command,
            check=check,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env is not None else None,
        )
    except subprocess.TimeoutExpired as exc:
        quoted = " ".join(shlex.quote(arg) for arg in command)
        raise CommandError(f"Command timed out after {timeout}s: {quoted}") from exc
    except subprocess.CalledProcessError as exc:
        quoted = " ".join(shlex.quote(arg) for arg in exc.cmd)
        raise CommandError(f"Command failed ({exc.returncode}): {quoted}") from exc


__all__ = ["Command", "CommandError", "ensure_tool", "run", "run_cmd", "which"]
