"""CLI coverage for the MCP command group."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from forensic.cli import cli


def _parse_cli_json(output: str) -> dict[str, object]:
    start = output.find("{")
    assert start >= 0, output
    return json.loads(output[start:])


def test_mcp_expose_outputs_deterministic_catalog(tmp_path: Path) -> None:
    runner = CliRunner()
    workspace = tmp_path / "workspace"
    result = runner.invoke(cli, ["--workspace", str(workspace), "mcp", "expose"])
    assert result.exit_code == 0, result.output
    payload = _parse_cli_json(result.output)

    assert payload["metadata"]["total_tools"] >= 10
    expected_categories = {"diagnostics", "cases", "modules", "reports", "router", "other"}
    assert set(payload["tools"].keys()) == expected_categories

    for entries in payload["tools"].values():
        names = [entry["name"] for entry in entries]
        assert names == sorted(names)

    tool_names = payload["metadata"]["tool_names"]
    assert tool_names == sorted(tool_names)


def test_mcp_status_reports_kali_and_forensic(tmp_path: Path) -> None:
    runner = CliRunner()
    workspace = tmp_path / "workspace"
    result = runner.invoke(
        cli,
        ["--workspace", str(workspace), "--json", "mcp", "status"],
    )
    assert result.exit_code == 0, result.output
    payload = _parse_cli_json(result.output)
    servers = payload["data"]["servers"]
    names = sorted(entry["name"] for entry in servers)
    assert names == ["forensic", "kali"]


def test_mcp_run_local_ping(tmp_path: Path) -> None:
    runner = CliRunner()
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
    assert payload["data"]["tool"] == "diagnostics.ping"
    result_data = payload["data"]["result"]["data"]
    assert result_data["ok"] is True
