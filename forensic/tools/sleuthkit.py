"""Guarded wrapper for The Sleuth Kit command-line utilities."""

from __future__ import annotations

import shlex
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional, Tuple

from forensic.utils.cmd import CommandError, run_cmd

_CANDIDATE_BINARIES = ["tsk_version", "mmls", "fls"]
_CAPABILITIES = ["mmls", "fls", "icat"]


def _first_available() -> Optional[str]:
    for binary in _CANDIDATE_BINARIES:
        path = which(binary)
        if path:
            return path
    return None


def _command_string(command: List[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def available() -> bool:
    """Return ``True`` when at least one Sleuth Kit binary is on PATH."""

    return _first_available() is not None


def version() -> Optional[str]:
    """Return the tool version if available, otherwise ``None``."""

    if not available():
        return None

    for binary in ("tsk_version", "mmls", "fls"):
        path = which(binary)
        if not path:
            continue
        command = [path]
        if binary != "tsk_version":
            command.append("-V")
        try:
            result = run_cmd(command, timeout=30)
        except CommandError:
            continue
        if result.stdout:
            return result.stdout.strip().splitlines()[0]
        if result.stderr:
            return result.stderr.strip().splitlines()[0]
    return None


def requirements() -> List[str]:
    """Return the preferred binaries for diagnostics output."""

    return list(_CANDIDATE_BINARIES)


def capabilities() -> List[str]:
    """Return a list of high-level capabilities supported by the wrapper."""

    return list(_CAPABILITIES)


def run_mmls(args: Dict[str, object]) -> Tuple[int, str, str]:
    """Execute ``mmls`` in a read-only fashion or provide a dry-run preview."""

    if not available():
        hint = "TOOL MISSING: expected one of {} on PATH".format(
            ", ".join(_CANDIDATE_BINARIES)
        )
        return (0, "", hint)

    dry_run = bool(args.get("dry_run", False))
    image_arg = args.get("image")
    image_path: Optional[Path] = None
    if image_arg:
        image_path = Path(str(image_arg))
        if not image_path.exists():
            return (1, "", f"IMAGE NOT FOUND: {image_path}")

    mmls_binary = which("mmls")
    command: List[str]
    if mmls_binary and image_path:
        command = [mmls_binary, str(image_path)]
    elif mmls_binary:
        command = [mmls_binary, "-V"]
    else:
        fallback = _first_available()
        if not fallback:
            return (0, "", "TOOL MISSING: Sleuth Kit utilities not available")
        command = [fallback]
        if Path(fallback).name != "tsk_version":
            command.append("-V")

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
    "run_mmls",
]
