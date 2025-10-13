"""Integration tests for the router CLI helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from forensic.cli import cli as forensic_cli
from forensic.modules.router import pipeline as router_pipeline
from forensic.modules.router.common import RouterResult


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_router_help_lists_subcommands(runner: CliRunner) -> None:
    result = runner.invoke(forensic_cli, ["router", "--help"])
    assert result.exit_code == 0
    assert "capture" in result.output
    assert "extract" in result.output
    assert "manifest" in result.output


def test_env_init_dry_run(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        result = runner.invoke(
            forensic_cli,
            ["router", "env", "init", "--root", "cases/router_demo", "--dry-run"],
        )
        assert result.exit_code == 0
        assert "Dry-run" in result.output
        assert "router_demo" in result.output


def test_capture_start_requires_enable_flag(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        result = runner.invoke(
            forensic_cli,
            ["router", "capture", "start", "--if", "eth0"],
        )
        assert result.exit_code == 0
        assert "Live capture disabled" in result.output


def test_capture_start_missing_tool_guard(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    with runner.isolated_filesystem():
        monkeypatch.setattr(
            "forensic.modules.router.capture.shutil.which", lambda tool: None
        )
        result = runner.invoke(
            forensic_cli,
            [
                "router",
                "capture",
                "start",
                "--if",
                "eth0",
                "--enable-live-capture",
            ],
        )
        assert result.exit_code == 0
        assert "Required capture tool" in result.output


def test_extract_ui_generates_artifact(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        input_dir = Path("input")
        input_dir.mkdir()
        (input_dir / "index.html").write_text("<html>ui</html>", encoding="utf-8")
        (input_dir / "settings.json").write_text(
            '{\n  "ssid": "demo"\n}\n', encoding="utf-8"
        )

        output_dir = Path("out")
        result = runner.invoke(
            forensic_cli,
            [
                "router",
                "extract",
                "ui",
                "--input",
                str(input_dir),
                "--out",
                str(output_dir),
            ],
        )
        assert result.exit_code == 0
        files = list(output_dir.rglob("ui_artifacts.json"))
        assert files, "expected ui_artifacts.json to be created"
        artifact_file = files[0]
        data = json.loads(artifact_file.read_text(encoding="utf-8"))
        assert data["kind"] == "ui"
        assert sorted(entry["path"] for entry in data["artifacts"])
        coc_log = artifact_file.parent / "chain_of_custody.log"
        assert coc_log.exists()
        log_lines = {
            line.strip()
            for line in coc_log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        assert log_lines, "chain_of_custody log should contain entries"


def test_manifest_write_is_deterministic(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        source_dir = Path("router_extract")
        (source_dir / "data").mkdir(parents=True)
        (source_dir / "data" / "foo.txt").write_text("foo", encoding="utf-8")
        (source_dir / "data" / "bar.txt").write_text("bar", encoding="utf-8")

        manifest_path = Path("manifest.json")
        args = [
            "router",
            "manifest",
            "write",
            "--source",
            str(source_dir),
            "--out",
            str(manifest_path),
        ]
        result = runner.invoke(forensic_cli, args)
        assert result.exit_code == 0
        records = json.loads(manifest_path.read_text(encoding="utf-8"))
        paths = [record["path"] for record in records]
        assert paths == sorted(paths)

        log_file = source_dir / "chain_of_custody.log"
        before = log_file.read_text(encoding="utf-8")
        # Re-run to ensure provenance entries are not duplicated.
        result = runner.invoke(forensic_cli, args)
        assert result.exit_code == 0
        after = log_file.read_text(encoding="utf-8")
        assert before == after


def test_pipeline_run_invokes_handlers(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    calls: list[str] = []

    def _stub(name: str):
        def _inner(params: dict) -> RouterResult:
            calls.append(name)
            result = RouterResult()
            result.message = f"ran {name}"
            return result

        return _inner

    monkeypatch.setitem(router_pipeline.HANDLERS, "extract.ui", _stub("extract.ui"))
    monkeypatch.setitem(router_pipeline.HANDLERS, "summarize", _stub("summarize"))

    with runner.isolated_filesystem():
        result = runner.invoke(forensic_cli, ["router", "pipeline", "run"])
        assert result.exit_code == 0
        assert "Router pipeline completed" in result.output
        assert calls == ["extract.ui", "summarize"]

        dry_run = runner.invoke(
            forensic_cli, ["router", "pipeline", "run", "--dry-run"]
        )
        assert dry_run.exit_code == 0
        assert "Dry-run" in dry_run.output


def test_summarize_generates_markdown(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        analysis_dir = Path("analysis")
        analysis_dir.mkdir()
        (analysis_dir / "ui.json").write_text("{}", encoding="utf-8")

        output_path = Path("summary.md")
        result = runner.invoke(
            forensic_cli,
            [
                "router",
                "summarize",
                "--in",
                str(analysis_dir),
                "--out",
                str(output_path),
            ],
        )
        assert result.exit_code == 0
        text = output_path.read_text(encoding="utf-8")
        assert text.startswith("# Router Forensic Summary")
        assert "Total files" in text


def test_pipeline_legacy_dry_run(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    with runner.isolated_filesystem():
        # Simulate missing legacy script to ensure guard message is emitted.
        monkeypatch.setattr(
            "forensic.modules.router.pipeline.legacy_invocation",
            lambda script, args, dry_run=False: RouterResult().guard(
                "Legacy script run_forensic_pipeline.sh is not available.",
                status="skipped",
            ),
        )
        result = runner.invoke(
            forensic_cli,
            ["router", "pipeline", "run", "--legacy", "--dry-run"],
        )
        assert result.exit_code == 0
        assert "Legacy script" in result.output
