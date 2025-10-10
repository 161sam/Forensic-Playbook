"""Guarded interactions with Sleuthkit command line tools."""

from __future__ import annotations

import shlex
from pathlib import Path
from shutil import which
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from forensic.utils.cmd import CommandError, run as run_cmd

_REQUIREMENTS = ["tsk_version", "mmls", "fls"]
_CAPABILITIES = ["version", "mmls", "fls"]
_DEFAULT_TIMEOUT = 30


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
    """Return ``True`` when any Sleuthkit binary is reachable."""

    return _first_available(_REQUIREMENTS) is not None


def version() -> Optional[str]:
    """Return the Sleuthkit version string if it can be determined."""

    executable = _first_available(["tsk_version", "mmls", "fls"])
    if not executable:
        return None

    if executable == "tsk_version":
        command = ["tsk_version"]
    else:
        command = [executable, "-V"]

    code, stdout, stderr = _execute(command)
    if code == 0:
        output = stdout or stderr
        return output.strip() or None
    return None


def requirements() -> List[str]:
    """Return the preferred command line tools for Sleuthkit support."""

    return list(_REQUIREMENTS)


def capabilities() -> List[str]:
    """Describe the guarded capabilities exposed by this wrapper."""

    return list(_CAPABILITIES)


def run_tsk_version(args: Dict[str, object] | None = None) -> Tuple[int, str, str]:
    """Execute ``tsk_version`` to report the installed version."""

    args = args or {}
    dry_run = bool(args.get("dry_run", False))

    executable = _first_available(["tsk_version", "mmls"])
    if not executable:
        return (0, "", "TOOL MISSING: install sleuthkit (tsk_version/mmls)")

    command = [executable] if executable == "tsk_version" else [executable, "-V"]
    return _execute(command, dry_run=dry_run)


def run_mmls_version(args: Dict[str, object] | None = None) -> Tuple[int, str, str]:
    """Run ``mmls -V`` for a lightweight version banner."""

    args = args or {}
    dry_run = bool(args.get("dry_run", False))

    executable = _first_available(["mmls"])
    if not executable:
        return (0, "", "TOOL MISSING: install sleuthkit (mmls)")

    command = [executable, "-V"]
    return _execute(command, dry_run=dry_run)


def run_fls_listing(args: Dict[str, object] | None = None) -> Tuple[int, str, str]:
    """Perform a guarded ``fls`` listing when an image path is available."""

    args = args or {}
    dry_run = bool(args.get("dry_run", False))
    image = args.get("image")
    recursive = bool(args.get("recursive", True))

    executable = _first_available(["fls"])
    if not executable:
        return (0, "", "TOOL MISSING: install sleuthkit (fls)")

    if not image:
        return (0, "", "No image supplied; provide 'image' for fls analysis")

    image_path = Path(str(image))
    if not image_path.exists():
        return (0, "", f"Image does not exist: {image_path}")

    command = [executable]
    if recursive:
        command.append("-r")
    command.extend(["-m", "/", str(image_path)])

    timeout = int(args.get("timeout", _DEFAULT_TIMEOUT))
    return _execute(command, dry_run=dry_run, timeout=timeout)


__all__ = [
    "available",
    "capabilities",
    "requirements",
    "run_fls_listing",
    "run_mmls_version",
    "run_tsk_version",
    "version",
]
