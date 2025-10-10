"""Mock-friendly connector for the Kali MCP server."""

from __future__ import annotations

import os
from typing import Mapping

from .types import ServerStatus

_ALLOWED = {"available", "unavailable", "unknown"}


def _normalise(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in _ALLOWED:
        return lowered
    return "unknown"


def status(env: Mapping[str, str] | None = None) -> ServerStatus:
    """Return the status of the Kali MCP connector.

    The connector is intentionally light-weight: it never performs network
    requests during tests. Behaviour can be influenced using environment
    variables for deterministic mocks:

    ``FORENSIC_MCP_KALI_STATUS``
        Force a particular availability flag (``available`` / ``unavailable`` /
        ``unknown``).
    ``FORENSIC_MCP_KALI_ENDPOINT``
        Document the configured endpoint in the returned metadata.
    """

    environment = dict(os.environ)
    environment.update(env or {})

    forced_status = environment.get("FORENSIC_MCP_KALI_STATUS")
    if forced_status:
        return ServerStatus(
            name="kali",
            status=_normalise(forced_status),
            message="Status forced via FORENSIC_MCP_KALI_STATUS",
            data={"endpoint": environment.get("FORENSIC_MCP_KALI_ENDPOINT", "n/a")},
        )

    endpoint = environment.get("FORENSIC_MCP_KALI_ENDPOINT")
    if endpoint:
        return ServerStatus(
            name="kali",
            status="available",
            message="Endpoint configured",
            data={"endpoint": endpoint},
        )

    return ServerStatus(
        name="kali",
        status="unknown",
        message="No Kali MCP endpoint configured",
        data={"endpoint": "n/a"},
    )
