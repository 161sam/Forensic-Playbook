"""Guarded helper for YARA scanning."""

from __future__ import annotations

import shlex
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional, Sequence, Tuple

from forensic.utils.cmd import CommandError, run as run_cmd

_EXECUTABLE = "yara"
_CAPABILITIES = ["version", "scan"]
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
    """Return ``True`` if the ``yara`` binary is present."""

    return which(_EXECUTABLE) is not None


def version() -> Optional[str]:
    """Return the YARA version string if retrievable."""

    if not available():
        return None

    code, stdout, stderr = _execute([_EXECUTABLE, "--version"])
    if code == 0:
        output = stdout or stderr
        return output.strip() or None
    return None


def requirements() -> List[str]:
    """Return the binary name expected for YARA support."""

    return [_EXECUTABLE]


def capabilities() -> List[str]:
    """Describe high-level capabilities of the YARA wrapper."""

    return list(_CAPABILITIES)


def run_version(args: Dict[str, object] | None = None) -> Tuple[int, str, str]:
    """Execute ``yara --version`` safely."""

    args = args or {}
    dry_run = bool(args.get("dry_run", False))

    if not available():
        return (0, "", "TOOL MISSING: install yara")

    command = [_EXECUTABLE, "--version"]
    timeout = int(args.get("timeout", _DEFAULT_TIMEOUT))
    return _execute(command, dry_run=dry_run, timeout=timeout)


def run_scan(args: Dict[str, object] | None = None) -> Tuple[int, str, str]:
    """Perform a guarded scan using ``yara`` with safe defaults."""

    args = args or {}
    dry_run = bool(args.get("dry_run", False))

    if not available():
        return (0, "", "TOOL MISSING: install yara")

    rule_path = args.get("rule") or args.get("rule_file")
    target_path = args.get("target") or args.get("path")
    recursive = bool(args.get("recursive", False))

    if not rule_path or not target_path:
        preview = [_EXECUTABLE, "-s", "--no-follow-symlinks", "RULES", "TARGET"]
        code, stdout, stderr = _execute(preview, dry_run=True)
        message = "Provide 'rule' and 'target' arguments to perform a scan"
        return (code, stdout, message)

    rule = Path(str(rule_path))
    target = Path(str(target_path))

    if not rule.exists():
        return (0, "", f"Rule file does not exist: {rule}")
    if not target.exists():
        return (0, "", f"Target path does not exist: {target}")

    command = [_EXECUTABLE, "-s", "--no-follow-symlinks"]
    if recursive:
        command.append("-r")
    command.extend([str(rule), str(target)])

    timeout = int(args.get("timeout", _DEFAULT_TIMEOUT))
    return _execute(command, dry_run=dry_run, timeout=timeout)


__all__ = [
    "available",
    "capabilities",
    "requirements",
    "run_scan",
    "run_version",
    "version",
]
