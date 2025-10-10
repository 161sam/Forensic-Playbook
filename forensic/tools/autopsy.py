"""Guarded wrapper for the Autopsy forensic suite."""

from __future__ import annotations

from pathlib import Path
from shutil import which
from typing import Dict, List, Optional, Tuple

_CAPABILITIES = ["gui", "case_management", "timeline", "ingest"]
_REQUIREMENTS = ["autopsy", "autopsy64.exe"]


def available() -> bool:
    """Return whether an Autopsy launcher is present on PATH."""

    return any(which(binary) for binary in _REQUIREMENTS)


def version() -> Optional[str]:
    """Return ``None`` because Autopsy does not expose a stable CLI version switch."""

    return None


def requirements() -> List[str]:
    """List the binaries inspected to locate Autopsy."""

    return list(_REQUIREMENTS)


def capabilities() -> List[str]:
    """Return high-level capabilities for documentation purposes."""

    return list(_CAPABILITIES)


def run_headless_hint(args: Dict[str, object]) -> Tuple[int, str, str]:
    """Provide guidance for Autopsy usage within guardrails."""

    dry_run = bool(args.get("dry_run", False))
    launcher = next((which(binary) for binary in _REQUIREMENTS if which(binary)), None)
    if dry_run:
        if launcher:
            return (0, launcher, "")
        return (0, "autopsy", "TOOL MISSING: Autopsy launcher not found on PATH")

    if not launcher:
        return (0, "", "TOOL MISSING: Autopsy launcher not found on PATH")

    message = (
        "Autopsy is typically executed via its GUI. Launch manually at: "
        f"{Path(launcher)}"
    )
    return (0, "", message)


__all__ = [
    "available",
    "version",
    "requirements",
    "capabilities",
    "run_headless_hint",
]
