"""Guarded wrapper for the bulk_extractor utility."""

from __future__ import annotations

import shlex
from shutil import which
from typing import Dict, List, Optional, Tuple

from forensic.utils.cmd import CommandError, run_cmd

_BINARY = "bulk_extractor"
_CAPABILITIES = ["bulk_extractor", "bulk_diff"]


def _command_string(command: List[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def available() -> bool:
    """Return whether ``bulk_extractor`` is on PATH."""

    return which(_BINARY) is not None


def version() -> Optional[str]:
    """Return the tool version if available."""

    if not available():
        return None
    try:
        result = run_cmd([_BINARY, "-V"], timeout=30)
    except CommandError:
        return None
    output = result.stdout.strip() or result.stderr.strip()
    if output:
        return output.splitlines()[0]
    return None


def requirements() -> List[str]:
    """List the binaries inspected to determine availability."""

    return [_BINARY]


def capabilities() -> List[str]:
    """Return high-level capabilities supported by the wrapper."""

    return list(_CAPABILITIES)


def run_version(args: Dict[str, object]) -> Tuple[int, str, str]:
    """Run the version command or provide a dry-run preview."""

    if not available():
        return (0, "", "TOOL MISSING: bulk_extractor not found on PATH")

    dry_run = bool(args.get("dry_run", False))
    command = [_BINARY, "-V"]
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
    "run_version",
]
