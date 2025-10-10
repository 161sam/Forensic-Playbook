"""Guarded helper describing the Autopsy forensic suite."""

from __future__ import annotations

from shutil import which
from typing import Dict, List, Optional, Tuple

_REQUIREMENTS = ["autopsy", "autopsy64"]
_CAPABILITIES = ["case-management", "gui"]


def available() -> bool:
    """Return ``True`` if an Autopsy launcher can be located."""

    return any(which(binary) for binary in _REQUIREMENTS)


def version() -> Optional[str]:
    """Autopsy does not expose a stable CLI version flag; return ``None``."""

    return None


def requirements() -> List[str]:
    """Return launchers considered for Autopsy detection."""

    return list(_REQUIREMENTS)


def capabilities() -> List[str]:
    """Describe the guarded functionality offered by this wrapper."""

    return list(_CAPABILITIES)


def run_launch_hint(args: Dict[str, object] | None = None) -> Tuple[int, str, str]:
    """Return guidance on running Autopsy in GUI/headless modes."""

    args = args or {}
    dry_run = bool(args.get("dry_run", False))

    if not available():
        return (0, "", "TOOL MISSING: install Autopsy to use the GUI suite")

    if dry_run:
        return (0, "Autopsy launch requires GUI/headless setup", "")

    message = (
        "Autopsy must be started manually. Use the GUI launcher or refer to "
        "the official documentation for headless ingestion options."
    )
    return (0, message, "")


__all__ = [
    "available",
    "capabilities",
    "requirements",
    "run_launch_hint",
    "version",
]
