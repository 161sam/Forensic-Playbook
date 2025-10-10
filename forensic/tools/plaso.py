"""Guarded wrapper for Plaso timeline tooling."""

from __future__ import annotations

import shlex
from shutil import which
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from forensic.utils.cmd import CommandError
from forensic.utils.cmd import run as run_cmd

_EXECUTABLES = ["log2timeline.py", "psort.py"]
_CAPABILITIES = ["timeline", "psort"]
_DEFAULT_TIMEOUT = 60


def _first_available(candidates: Iterable[str]) -> Optional[str]:
    for name in candidates:
        if which(name):
            return name
    return None


def _execute(
    command: Sequence[str], *, dry_run: bool = False, timeout: int = _DEFAULT_TIMEOUT
) -> Tuple[int, str, str]:
    rendered = " ".join(shlex.quote(arg) for arg in command)
    if dry_run:
        return (0, f"DRY RUN: {rendered}", "")

    try:
        result = run_cmd(command, timeout=timeout)
        return (result.returncode, result.stdout, result.stderr)
    except CommandError as exc:
        return (1, "", str(exc))


def available() -> bool:
    """Return whether a Plaso binary can be executed."""

    return _first_available(_EXECUTABLES) is not None


def version() -> Optional[str]:
    """Return a version banner if Plaso is installed."""

    executable = _first_available(["log2timeline.py", "psort.py"])
    if not executable:
        return None

    code, stdout, stderr = _execute([executable, "--version"])
    if code == 0:
        output = stdout or stderr
        return output.strip() or None
    return None


def requirements() -> List[str]:
    """Return binaries considered for Plaso integration."""

    return list(_EXECUTABLES)


def capabilities() -> List[str]:
    """Describe the read-only helpers exposed by the wrapper."""

    return list(_CAPABILITIES)


def run_log2timeline_version(args: Dict[str, object] | None = None) -> Tuple[int, str, str]:
    """Execute ``log2timeline.py --version`` safely."""

    args = args or {}
    dry_run = bool(args.get("dry_run", False))

    executable = _first_available(["log2timeline.py"])
    if not executable:
        return (0, "", "TOOL MISSING: install Plaso (log2timeline.py)")

    command = [executable, "--version"]
    timeout = int(args.get("timeout", _DEFAULT_TIMEOUT))
    return _execute(command, dry_run=dry_run, timeout=timeout)


def run_psort_version(args: Dict[str, object] | None = None) -> Tuple[int, str, str]:
    """Execute ``psort.py --version`` safely."""

    args = args or {}
    dry_run = bool(args.get("dry_run", False))

    executable = _first_available(["psort.py"])
    if not executable:
        return (0, "", "TOOL MISSING: install Plaso (psort.py)")

    command = [executable, "--version"]
    timeout = int(args.get("timeout", _DEFAULT_TIMEOUT))
    return _execute(command, dry_run=dry_run, timeout=timeout)


__all__ = [
    "available",
    "capabilities",
    "requirements",
    "run_log2timeline_version",
    "run_psort_version",
    "version",
]
