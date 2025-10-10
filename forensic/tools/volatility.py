"""Guarded helper for interacting with Volatility memory analysis tooling."""

from __future__ import annotations

import importlib
import shlex
from importlib.util import find_spec
from pathlib import Path
from shutil import which
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from forensic.utils.cmd import CommandError, run as run_cmd

_EXECUTABLES = ["volatility3", "vol", "vol.py"]
_CAPABILITIES = ["pslist", "info"]
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


def _module_available() -> bool:
    return find_spec("volatility3") is not None


def available() -> bool:
    """Return whether Volatility is accessible."""

    return _first_available(_EXECUTABLES) is not None or _module_available()


def version() -> Optional[str]:
    """Attempt to read the Volatility version string."""

    executable = _first_available(["volatility3", "vol"])
    if executable:
        code, stdout, stderr = _execute([executable, "--version"])
        if code == 0:
            output = stdout or stderr
            return output.strip() or None

    if _module_available():
        try:
            module = importlib.import_module("volatility3")
        except Exception:
            return None
        return getattr(module, "__version__", None)

    return None


def requirements() -> List[str]:
    """Return preferred binaries/modules for Volatility integration."""

    return [*_EXECUTABLES, "volatility3 (python module)"]


def capabilities() -> List[str]:
    """Describe guarded Volatility interactions."""

    return list(_CAPABILITIES)


def run_pslist(args: Dict[str, object] | None = None) -> Tuple[int, str, str]:
    """Execute a guarded ``pslist`` command when possible."""

    args = args or {}
    dry_run = bool(args.get("dry_run", False))
    limit = int(args.get("limit", 15))
    memory_image = args.get("memory") or args.get("memory_image")

    executable = _first_available(_EXECUTABLES)
    if not executable:
        if _module_available():
            return (
                0,
                "",
                "Volatility Python module present but CLI binary missing; use python -m volatility3",
            )
        return (0, "", "TOOL MISSING: install volatility3 or vol binary")

    if not memory_image:
        command = [executable, "-h"] if executable == "vol" else [executable, "--help"]
        code, stdout, stderr = _execute(command, dry_run=True)
        message = "Provide 'memory' path to execute pslist"
        return (code, stdout, message)

    memory_path = Path(str(memory_image))
    if not memory_path.exists():
        return (0, "", f"Memory image does not exist: {memory_path}")

    if executable == "volatility3":
        command = [executable, "-f", str(memory_path), "windows.pslist", "--limit", str(limit)]
    else:
        command = [executable, "-f", str(memory_path), "pslist", "--output", "table"]
        command.extend(["--output-file", "-"])

    timeout = int(args.get("timeout", _DEFAULT_TIMEOUT))
    return _execute(command, dry_run=dry_run, timeout=timeout)


def run_info(args: Dict[str, object] | None = None) -> Tuple[int, str, str]:
    """Display Volatility information output."""

    args = args or {}
    dry_run = bool(args.get("dry_run", False))

    executable = _first_available(["volatility3", "vol"])
    if not executable:
        return (0, "", "TOOL MISSING: install volatility3 or vol binary")

    command = [executable, "--info"]
    timeout = int(args.get("timeout", _DEFAULT_TIMEOUT))
    return _execute(command, dry_run=dry_run, timeout=timeout)


__all__ = [
    "available",
    "capabilities",
    "requirements",
    "run_info",
    "run_pslist",
    "version",
]
