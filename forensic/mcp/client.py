"""Lightweight HTTP client for interacting with MCP servers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests

from .config import MCPConfig


@dataclass(slots=True)
class MCPResponse:
    """Wrapper around responses returned by :class:`MCPClient`."""

    ok: bool
    status: Optional[int]
    data: Any = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "data": self.data,
            "error": self.error,
        }


class MCPClient:
    """HTTP client for the Forensic MCP endpoints."""

    def __init__(
        self, config: MCPConfig, *, session: Optional[requests.Session] = None
    ) -> None:
        self.config = config
        self.session = session or requests.Session()

    def close(self) -> None:
        """Close the underlying :class:`requests.Session`."""

        self.session.close()

    def _url(self, path: str) -> str:
        base = self.config.endpoint.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))

    def _request(self, method: str, path: str, **kwargs: Any) -> MCPResponse:
        url = self._url(path)
        headers = kwargs.pop("headers", {})
        headers.update(self.config.headers)
        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                timeout=self.config.timeout,
                **kwargs,
            )
        except requests.RequestException as exc:
            status_code = exc.response.status_code if exc.response else None
            return MCPResponse(ok=False, status=status_code, error=str(exc))

        payload: Any
        content_type = response.headers.get("Content-Type", "")
        if "json" in content_type:
            try:
                payload = response.json()
            except json.JSONDecodeError:
                payload = response.text
        else:
            payload = response.text

        if not response.ok:
            error_msg = payload if isinstance(payload, str) else json.dumps(payload)
            return MCPResponse(ok=False, status=response.status_code, error=error_msg)

        return MCPResponse(ok=True, status=response.status_code, data=payload)

    def status(self) -> MCPResponse:
        """Perform a health check against the MCP endpoint."""

        return self._request("GET", "/")

    def list_tools(self) -> MCPResponse:
        """Retrieve tool catalogue from the MCP server."""

        return self._request("GET", "/tools")

    def run_tool(self, tool: str, arguments: Dict[str, Any]) -> MCPResponse:
        """Execute an MCP tool via POST /tools/run."""

        payload = {"tool": tool, "arguments": arguments}
        return self._request("POST", "/tools/run", json=payload)
