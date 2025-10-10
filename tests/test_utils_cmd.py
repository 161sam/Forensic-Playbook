from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from forensic.utils import cmd as cmd_utils


def test_ensure_tool_returns_path(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_which(tool: str) -> str:
        assert tool == "demo-tool"
        return "/usr/bin/demo-tool"

    monkeypatch.setattr(cmd_utils, "which", fake_which)

    result = cmd_utils.ensure_tool("demo-tool")
    assert result == "/usr/bin/demo-tool"


def test_ensure_tool_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cmd_utils, "which", lambda tool: None)

    with pytest.raises(cmd_utils.CommandError) as exc:
        cmd_utils.ensure_tool("missing-tool")

    assert "missing-tool" in str(exc.value)


def test_run_executes_command(tmp_path: Path) -> None:
    result = cmd_utils.run(
        [Path(sys.executable), "-c", "print('hello world')"], cwd=tmp_path
    )

    assert result.stdout.strip() == "hello world"
    assert result.stderr == ""


@pytest.mark.parametrize("invalid", ["echo hello", []])
def test_run_validates_command_input(invalid) -> None:
    with pytest.raises((TypeError, ValueError)):
        cmd_utils.run(invalid)  # type: ignore[arg-type]


def test_run_validates_timeout() -> None:
    with pytest.raises(ValueError):
        cmd_utils.run([sys.executable, "-c", "pass"], timeout=0)


def test_run_handles_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["demo"], timeout=5)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(cmd_utils.CommandError) as exc:
        cmd_utils.run(["demo"], timeout=10)

    assert "timed out" in str(exc.value)


def test_run_handles_called_process_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            2, ["demo", "--flag"]
        )  # pragma: no cover - repr

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(cmd_utils.CommandError) as exc:
        cmd_utils.run(["demo"])

    assert "Command failed" in str(exc.value)


def test_run_rejects_unsupported_argument_type() -> None:
    with pytest.raises(TypeError):
        cmd_utils.run([object()])
