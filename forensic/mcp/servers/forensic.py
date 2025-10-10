"""Guarded connector for the built-in Forensic MCP server."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

from .types import ServerStatus

_ALLOWED = {"available", "unavailable", "unknown"}


def _normalise(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in _ALLOWED:
        return lowered
    return "unknown"


def _socket_present(socket_path: str | None) -> bool:
    if not socket_path:
        return False
    try:
        return Path(socket_path).exists()
    except OSError:
        return False


def status(env: Mapping[str, str] | None = None) -> ServerStatus:
    """Return the status of the local Forensic MCP connector."""

    environment = dict(os.environ)
    environment.update(env or {})

    forced_status = environment.get("FORENSIC_MCP_FORENSIC_STATUS")
    socket_path = environment.get("FORENSIC_MCP_FORENSIC_SOCKET")

    if forced_status:
        return ServerStatus(
            name="forensic",
            status=_normalise(forced_status),
            message="Status forced via FORENSIC_MCP_FORENSIC_STATUS",
            data={"socket": socket_path or "n/a"},
        )

    if _socket_present(socket_path):
        return ServerStatus(
            name="forensic",
            status="available",
            message="Control socket detected",
            data={"socket": socket_path},
        )

    return ServerStatus(
        name="forensic",
        status="unknown",
        message="No running forensic MCP server detected",
        data={"socket": socket_path or "n/a"},
    )
