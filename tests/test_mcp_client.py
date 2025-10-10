from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest
from click.testing import CliRunner

from forensic import build_mcp_tool_payload
from forensic.cli import cli
from forensic.mcp.client import MCPClient, MCPConfig, MCPResponse
from forensic.core.framework import ForensicFramework


class StubResponse:
    def __init__(self, *, ok: bool, status: int, data: Any = None, text: str = "") -> None:
        self.ok = ok
        self.status_code = status
        self._data = data
        self.text = text
        self.headers = {"Content-Type": "application/json" if isinstance(data, (dict, list)) else "text/plain"}

    def json(self) -> Any:
        if isinstance(self._data, (dict, list)):
            return self._data
        raise json.JSONDecodeError("", "", 0)


@pytest.fixture(name="runner")
def _runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(name="framework")
def _framework(tmp_path: Path) -> ForensicFramework:
    return ForensicFramework(workspace=tmp_path / "framework-workspace")


def _parse_cli_json(output: str) -> Dict[str, Any]:
    start = output.find("{")
    assert start >= 0, output
    return json.loads(output[start:])


def test_mcp_expose_outputs_sorted_json(runner: CliRunner, tmp_path) -> None:
    workspace = tmp_path / "workspace"
    result = runner.invoke(cli, ["--workspace", str(workspace), "mcp", "expose"])
    assert result.exit_code == 0, result.output
    payload = _parse_cli_json(result.output)
    names = [tool["name"] for tool in payload["tools"]]
    assert names == sorted(names)
    assert "router.env.init" in names
    assert payload["prompt"]["resource"] == "forensic/mcp/prompts/forensic_mode.txt"


def test_mcp_status_handles_connection_error(monkeypatch: pytest.MonkeyPatch, runner: CliRunner, tmp_path) -> None:
    def _raise(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        from requests import exceptions

        raise exceptions.ConnectionError("unreachable")

    monkeypatch.setattr("requests.Session.request", _raise)
    workspace = tmp_path / "workspace"
    result = runner.invoke(
        cli,
        ["--workspace", str(workspace), "--json", "mcp", "status"],
    )
    assert result.exit_code == 1
    payload = _parse_cli_json(result.output)
    assert payload["status"] == "error"
    assert payload["command"] == "mcp.status"
    assert payload["errors"]


def test_mcp_run_local_success(tmp_path, runner: CliRunner) -> None:
    workspace = tmp_path / "workspace"
    result = runner.invoke(
        cli,
        [
            "--workspace",
            str(workspace),
            "--json",
            "mcp",
            "run",
            "diagnostics.ping",
            "--local",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = _parse_cli_json(result.output)
    assert payload["command"] == "mcp.run.local"
    assert payload["status"] == "success"
    assert payload["data"]["tool"] == "diagnostics.ping"


def test_mcp_run_local_router_env(tmp_path, runner: CliRunner) -> None:
    workspace = tmp_path / "workspace"
    result = runner.invoke(
        cli,
        [
            "--workspace",
            str(workspace),
            "--json",
            "mcp",
            "run",
            "router.env.init",
            "--local",
            "--arg",
            f"root={workspace / 'router'}",
            "--arg",
            "dry_run=true",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = _parse_cli_json(result.output)
    assert payload["command"] == "mcp.run.local"
    assert payload["status"] == "success"
    data = payload["data"]["result"]["data"]
    assert data["payload"]["directories"]


def test_mcp_run_remote_success(monkeypatch: pytest.MonkeyPatch, runner: CliRunner, tmp_path) -> None:
    def _fake_request(self, method: str, url: str, **_kwargs: Dict[str, Any]):  # type: ignore[no-untyped-def]
        assert method == "POST"
        assert url.endswith("/tools/run")
        return StubResponse(ok=True, status=200, data={"status": "ok", "result": 42})

    monkeypatch.setattr("requests.Session.request", _fake_request)
    workspace = tmp_path / "workspace"
    result = runner.invoke(
        cli,
        [
            "--workspace",
            str(workspace),
            "--json",
            "mcp",
            "run",
            "diagnostics.ping",
            "--arg",
            "case_id=demo",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = _parse_cli_json(result.output)
    assert payload["status"] == "success"
    assert payload["data"]["response"] == {"status": "ok", "result": 42}


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


def test_build_expose_payload_sorted(framework: Any) -> None:
    payload = build_mcp_tool_payload(framework)
    names = [tool["name"] for tool in payload["tools"]]
    assert names == sorted(names)
