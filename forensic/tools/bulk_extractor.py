"""Guarded interactions with bulk_extractor."""

from __future__ import annotations

import shlex
from shutil import which
from typing import Dict, List, Optional, Sequence, Tuple

from forensic.utils.cmd import CommandError, run as run_cmd

_EXECUTABLE = "bulk_extractor"
_CAPABILITIES = ["version"]
_DEFAULT_TIMEOUT = 30


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
    """Return ``True`` when ``bulk_extractor`` is on PATH."""

    return which(_EXECUTABLE) is not None


def version() -> Optional[str]:
    """Return the ``bulk_extractor`` version banner if available."""

    if not available():
        return None

    code, stdout, stderr = _execute([_EXECUTABLE, "-V"])
    if code == 0:
        output = stdout or stderr
        return output.strip() or None
    return None


def requirements() -> List[str]:
    """Return the binary name expected for bulk_extractor."""

    return [_EXECUTABLE]


def capabilities() -> List[str]:
    """Describe the read-only helpers exposed by this wrapper."""

    return list(_CAPABILITIES)


def run_version(args: Dict[str, object] | None = None) -> Tuple[int, str, str]:
    """Execute ``bulk_extractor -V``."""

    args = args or {}
    dry_run = bool(args.get("dry_run", False))

    if not available():
        return (0, "", "TOOL MISSING: install bulk_extractor")

    command = [_EXECUTABLE, "-V"]
    timeout = int(args.get("timeout", _DEFAULT_TIMEOUT))
    return _execute(command, dry_run=dry_run, timeout=timeout)


__all__ = [
    "available",
    "capabilities",
    "requirements",
    "run_version",
    "version",
]
