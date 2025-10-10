"""Tests for the guarded Codex CLI group."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

requests_stub = types.ModuleType("requests")


class _StubSession:
    def close(self) -> None:  # pragma: no cover - trivial stub
        return None

    def request(self, *args, **kwargs):  # pragma: no cover - not exercised
        raise RuntimeError("requests stub invoked")


class _StubRequestException(Exception):
    def __init__(self, *args, response=None):
        super().__init__(*args)
        self.response = response


requests_stub.Session = _StubSession
requests_stub.RequestException = _StubRequestException
sys.modules.setdefault("requests", requests_stub)

import forensic.codex.installer as codex_installer
import forensic.codex.runner as codex_runner
from forensic.cli import cli


def _invoke(runner: CliRunner, args: list[str]) -> dict:
    result = runner.invoke(cli, args)
    assert result.exit_code == 0, result.output
    start = result.output.find("{")
    assert start >= 0, result.output
    return json.loads(result.output[start:])


def test_codex_install_dry_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runner = CliRunner()
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    called = False

    def fake_execute(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("installer should not run during dry-run")

    monkeypatch.setattr(codex_installer, "_execute_plan", fake_execute)

    payload = _invoke(
        runner,
        [
            "--workspace",
            str(workspace),
            "--json",
            "codex",
            "install",
            "--workspace",
            str(workspace),
            "--dry-run",
        ],
    )

    assert payload["command"] == "codex.install"
    assert payload["status"] == "success"
    data = payload["data"]
    assert data["dry_run"] is True
    assert data["paths"]["workspace"].endswith("workspace")
    assert data["plan"]["commands"]
    assert called is False


def test_codex_start_dry_run_foreground(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = CliRunner()
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    def fake_execute(*args, **kwargs):
        raise AssertionError("start script should not execute during dry-run")

    monkeypatch.setattr(codex_runner, "_execute_plan", fake_execute)

    payload = _invoke(
        runner,
        [
            "--workspace",
            str(workspace),
            "--json",
            "codex",
            "start",
            "--workspace",
            str(workspace),
            "--foreground",
            "--dry-run",
        ],
    )

    assert payload["command"] == "codex.start"
    assert payload["status"] == "success"
    data = payload["data"]
    assert data["dry_run"] is True
    assert data["foreground"] is True
    assert data["plan"]["commands"]


def test_codex_status_reports_metadata(tmp_path: Path) -> None:
    runner = CliRunner()
    workspace = tmp_path / "workspace"
    log_dir = workspace / "codex_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    meta_file = log_dir / "meta.jsonl"
    meta_file.write_text(
        json.dumps({"command": "install", "plan_hash": "abc", "timestamp": "2024-01-01T00:00:00"})
        + "\n",
        encoding="utf-8",
    )

    payload = _invoke(
        runner,
        [
            "--workspace",
            str(workspace),
            "--json",
            "codex",
            "status",
            "--workspace",
            str(workspace),
        ],
    )

    assert payload["command"] == "codex.status"
    assert payload["status"] == "success"
    data = payload["data"]
    assert data["running"] is False
    assert data["meta_file"].endswith("meta.jsonl")
    assert data["known_operations"]
    assert list(data.keys()) == sorted(data.keys())
