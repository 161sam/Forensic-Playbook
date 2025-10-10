"""Shared dataclasses for MCP server connector status reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass(slots=True)
class ServerStatus:
    """Structured status returned by MCP server connectors."""

    name: str
    status: str
    message: str | None = None
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "name": self.name,
            "status": self.status,
            "data": dict(self.data),
        }
        if self.message is not None:
            payload["message"] = self.message
        return payload
