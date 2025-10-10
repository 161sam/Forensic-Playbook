"""Guarded wrapper for Plaso (log2timeline/psort)."""

from __future__ import annotations

import shlex
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional, Tuple

from forensic.utils.cmd import CommandError, run_cmd

_LOG2TIMELINE = "log2timeline.py"
_PSORT = "psort.py"
_CAPABILITIES = ["log2timeline", "psort", "pinfo"]


def _command_string(command: List[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def _available_binaries() -> List[str]:
    binaries = []
    for candidate in (_LOG2TIMELINE, _PSORT):
        resolved = which(candidate)
        if resolved:
            binaries.append(resolved)
    return binaries


def available() -> bool:
    """Return whether either ``log2timeline.py`` or ``psort.py`` is present."""

    return bool(_available_binaries())


def version() -> Optional[str]:
    """Return the Plaso version string if available."""

    for binary in _available_binaries():
        try:
            result = run_cmd([binary, "--version"], timeout=30)
        except CommandError:
            continue
        output = result.stdout.strip() or result.stderr.strip()
        if output:
            return output.splitlines()[0]
    return None


def requirements() -> List[str]:
    """List binaries inspected by the wrapper."""

    return [_LOG2TIMELINE, _PSORT]


def capabilities() -> List[str]:
    """Return the high-level capabilities of the wrapper."""

    return list(_CAPABILITIES)


def run_log2timeline(args: Dict[str, object]) -> Tuple[int, str, str]:
    """Execute a guarded ``log2timeline`` preview command."""

    if not available():
        hint = "TOOL MISSING: expected log2timeline.py or psort.py on PATH"
        return (0, "", hint)

    dry_run = bool(args.get("dry_run", False))
    source_arg = args.get("source")
    source_path: Optional[Path] = None
    if source_arg:
        source_path = Path(str(source_arg))
        if not source_path.exists():
            return (1, "", f"SOURCE NOT FOUND: {source_path}")

    binary = which(_LOG2TIMELINE) or which(_PSORT)
    command = [binary or _LOG2TIMELINE, "--version"]
    if source_path:
        command = [binary or _LOG2TIMELINE, "--no_dependencies_check", "--logfile", "-", str(source_path)]

    if dry_run:
        return (0, _command_string(command), "")

    if len(command) > 2 and "--version" not in command:
        # Running log2timeline on actual data is heavyweight; guard by returning a message.
        return (
            0,
            "",
            "SAFEGUARD: log2timeline execution is disabled in wrapper; use dry_run for preview",
        )

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
    "run_log2timeline",
]
