"""Guarded wrapper for the YARA malware scanning utility."""

from __future__ import annotations

import shlex
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional, Tuple

from forensic.utils.cmd import CommandError, run_cmd

_BINARY = "yara"
_CAPABILITIES = ["scan", "compile", "list"]


def _command_string(command: List[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def available() -> bool:
    """Return whether ``yara`` is available on PATH."""

    return which(_BINARY) is not None


def version() -> Optional[str]:
    """Return the YARA version string if available."""

    if not available():
        return None
    try:
        result = run_cmd([_BINARY, "--version"], timeout=30)
    except CommandError:
        return None
    output = result.stdout.strip() or result.stderr.strip()
    if output:
        return output.splitlines()[0]
    return None


def requirements() -> List[str]:
    """List binaries inspected by the wrapper."""

    return [_BINARY]


def capabilities() -> List[str]:
    """Return high-level capabilities for diagnostics output."""

    return list(_CAPABILITIES)


def run_scan(args: Dict[str, object]) -> Tuple[int, str, str]:
    """Run a guarded YARA scan or provide a dry-run preview."""

    if not available():
        return (0, "", "TOOL MISSING: yara binary not found on PATH")

    dry_run = bool(args.get("dry_run", False))
    recursive = bool(args.get("recursive", False))
    print_strings = bool(args.get("print_strings", True))
    rules_arg = args.get("rules")
    target_arg = args.get("target")
    rules_path: Optional[Path] = None
    target_path: Optional[Path] = None

    if rules_arg:
        rules_path = Path(str(rules_arg))
        if not rules_path.exists():
            return (1, "", f"RULES NOT FOUND: {rules_path}")
    if target_arg:
        target_path = Path(str(target_arg))
        if not target_path.exists():
            return (1, "", f"TARGET NOT FOUND: {target_path}")

    command: List[str] = [_BINARY]
    if print_strings:
        command.append("-s")
    command.append("-n")
    if recursive:
        command.append("-r")

    if rules_path and target_path:
        command.extend([str(rules_path), str(target_path)])
    else:
        command = [_BINARY, "--version"]

    if dry_run:
        return (0, _command_string(command), "")

    if command[1] == "--version":
        try:
            result = run_cmd(command, timeout=int(args.get("timeout", 60)))
        except CommandError as exc:
            return (1, "", str(exc))
        return (result.returncode, result.stdout, result.stderr)

    if not bool(args.get("allow_execution", False)):
        return (
            0,
            "",
            "SAFEGUARD: actual YARA scans require allow_execution=True or use dry_run",
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
    "run_scan",
]
