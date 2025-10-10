"""MCP server connectors for guarded status checks."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping

from . import forensic, kali
from .types import ServerStatus


def list_statuses(env: Mapping[str, str] | None = None) -> list[ServerStatus]:
    """Return statuses for all built-in MCP connectors."""

    environment = dict(env or {})
    statuses = [
        kali.status(env=environment),
        forensic.status(env=environment),
    ]
    return statuses


def summarise(statuses: Iterable[ServerStatus]) -> Dict[str, Any]:
    """Summarise a set of statuses for CLI emission."""

    collected = [status.to_dict() for status in statuses]
    overall = "success"
    for status in collected:
        if status["status"] == "unavailable":
            overall = "error"
            break
        if status["status"] == "unknown" and overall == "success":
            overall = "warning"
    return {"statuses": collected, "overall": overall}


__all__ = ["ServerStatus", "list_statuses", "summarise"]
