"""Unit tests for MCP client helpers and catalogue builders."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from forensic import build_mcp_tool_payload
from forensic.core.framework import ForensicFramework
from forensic.mcp.client import MCPClient, MCPConfig, MCPResponse


@pytest.fixture(name="framework")
def _framework(tmp_path: Path) -> ForensicFramework:
    return ForensicFramework(workspace=tmp_path / "framework-workspace")


def test_mcp_client_handles_error(monkeypatch: pytest.MonkeyPatch) -> None:
    config = MCPConfig()

    def _fake_request(self, method: str, url: str, **_kwargs: Dict[str, Any]):  # type: ignore[no-untyped-def]
        from requests import RequestException

        raise RequestException("boom")

    monkeypatch.setattr("requests.Session.request", _fake_request)
    client = MCPClient(config)
    response = client.status()
    assert isinstance(response, MCPResponse)
    assert not response.ok
    assert response.error
    client.close()


def test_build_expose_payload_groups_tools(framework: ForensicFramework) -> None:
    payload = build_mcp_tool_payload(framework)
    assert set(payload["tools"].keys()) == {
        "diagnostics",
        "cases",
        "modules",
        "reports",
        "router",
        "other",
    }
    names = payload["metadata"]["tool_names"]
    assert names == sorted(names)
    assert payload["metadata"]["total_tools"] == len(names)
    assert payload["prompt"]["resource"] == "forensic/mcp/prompts/forensic_mode.txt"
