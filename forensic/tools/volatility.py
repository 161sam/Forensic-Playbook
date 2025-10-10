"""Guarded wrapper around Volatility memory forensics frameworks."""

from __future__ import annotations

import importlib.util
import shlex
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional, Tuple

from forensic.utils.cmd import CommandError, run_cmd

_CANDIDATE_BINARIES = ["volatility3", "vol", "vol.py"]
_CAPABILITIES = ["windows.pslist", "windows.pstree", "linux.pslist"]


def _module_available() -> bool:
    return importlib.util.find_spec("volatility3") is not None


def _preferred_binary() -> Optional[str]:
    for binary in _CANDIDATE_BINARIES:
        path = which(binary)
        if path:
            return path
    return None


def _command_string(command: List[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def available() -> bool:
    """Return whether a supported Volatility entry point is available."""

    return _preferred_binary() is not None or _module_available()


def version() -> Optional[str]:
    """Return the version string, if detectable."""

    binary = _preferred_binary()
    commands: List[List[str]] = []
    if binary:
        name = Path(binary).name
        if name == "volatility3":
            commands.append([binary, "--version"])
        else:
            commands.append([binary, "--version"])
            commands.append([binary, "--help"])
    if _module_available():
        commands.append(["python3", "-m", "volatility3", "--version"])

    for command in commands:
        try:
            result = run_cmd(command, timeout=30)
        except CommandError:
            continue
        output = result.stdout.strip() or result.stderr.strip()
        if output:
            return output.splitlines()[0]
    return None


def requirements() -> List[str]:
    """List the preferred binaries or modules for diagnostics output."""

    requirements: List[str] = list(_CANDIDATE_BINARIES)
    requirements.append("python3 -m volatility3")
    return requirements


def capabilities() -> List[str]:
    """Return the advertised capabilities for diagnostics purposes."""

    return list(_CAPABILITIES)


def run_pslist(args: Dict[str, object]) -> Tuple[int, str, str]:
    """Show a safe preview of the ``pslist`` functionality."""

    if not available():
        hint = "TOOL MISSING: expected one of {} or the volatility3 module".format(
            ", ".join(_CANDIDATE_BINARIES)
        )
        return (0, "", hint)

    dry_run = bool(args.get("dry_run", False))
    binary = _preferred_binary()
    if binary:
        name = Path(binary).name
        if name == "volatility3":
            command = [binary, "windows.pslist", "--help"]
        else:
            command = [binary, "--info"]
    else:
        command = ["python3", "-m", "volatility3", "--version"]

    if dry_run:
        return (0, _command_string(command), "")

    try:
        result = run_cmd(command, timeout=int(args.get("timeout", 60)))
    except CommandError as exc:
        return (1, "", str(exc))
    return (result.returncode, result.stdout, result.stderr)


__all__ = [
    "available",
    "version",
    "requirements",
    "capabilities",
    "run_pslist",
]
