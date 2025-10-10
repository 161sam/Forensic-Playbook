from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from forensic.cli import cli


def _invoke(runner: CliRunner, args: list[str]) -> tuple[int, dict]:
    result = runner.invoke(cli, args)
    assert result.exit_code == 0, result.output
    start = result.output.find("{")
    assert start >= 0, result.output
    payload = json.loads(result.output[start:])
    return result.exit_code, payload


def test_codex_install_dry_run(tmp_path: Path) -> None:
    runner = CliRunner()
    workspace = tmp_path / "workspace"
    args = [
        "--workspace",
        str(workspace),
        "--json",
        "codex",
        "install",
        "--workspace",
        str(workspace),
        "--dry-run",
    ]
    _, payload = _invoke(runner, args)
    assert payload["command"] == "codex.install"
    assert payload["status"] in {"success", "warning"}
    assert payload["data"]["dry_run"] is True
    assert payload["data"]["paths"]["workspace"].endswith("workspace")


def test_codex_start_reports_missing_repo(tmp_path: Path) -> None:
    runner = CliRunner()
    workspace = tmp_path / "workspace"
    args = [
        "--workspace",
        str(workspace),
        "--json",
        "codex",
        "start",
        "--workspace",
        str(workspace),
        "--dry-run",
    ]
    _, payload = _invoke(runner, args)
    assert payload["command"] == "codex.start"
    assert payload["status"] == "warning"
    assert "MCP repository" in payload["message"]


def test_codex_stop_without_pid(tmp_path: Path) -> None:
    runner = CliRunner()
    workspace = tmp_path / "workspace"
    args = [
        "--workspace",
        str(workspace),
        "--json",
        "codex",
        "stop",
        "--workspace",
        str(workspace),
        "--dry-run",
    ]
    _, payload = _invoke(runner, args)
    assert payload["command"] == "codex.stop"
    assert payload["status"] == "success"


def test_codex_status_reports_health(tmp_path: Path) -> None:
    runner = CliRunner()
    workspace = tmp_path / "workspace"
    args = [
        "--workspace",
        str(workspace),
        "--json",
        "codex",
        "status",
        "--workspace",
        str(workspace),
    ]
    _, payload = _invoke(runner, args)
    assert payload["command"] == "codex.status"
    assert payload["status"] in {"warning", "success"}
    assert payload["data"]["running"] is False
