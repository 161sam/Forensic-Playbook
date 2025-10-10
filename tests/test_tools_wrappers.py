"""Unit tests for the guarded forensic.tools wrappers."""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from forensic.tools import autopsy, bulk_extractor, plaso, sleuthkit, volatility, yara


def _result(stdout: str = "", stderr: str = "", returncode: int = 0) -> types.SimpleNamespace:
    """Return a simple object mimicking subprocess.CompletedProcess."""

    return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def test_sleuthkit_wrapper_reports_availability(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sleuthkit, "which", lambda name: f"/usr/bin/{name}" if name in {"mmls", "tsk_version"} else None)
    monkeypatch.setattr(sleuthkit, "run_cmd", lambda cmd, timeout=30: _result(stdout="sleuthkit 4.11\n"))

    assert sleuthkit.available() is True
    assert sleuthkit.version() == "sleuthkit 4.11"
    assert "mmls" in sleuthkit.requirements()
    assert "mmls" in sleuthkit.capabilities()

    image = tmp_path / "evidence.dd"
    image.write_bytes(b"\0")

    dry_rc, dry_stdout, dry_stderr = sleuthkit.run_mmls({"dry_run": True, "image": str(image)})
    assert dry_rc == 0
    assert "mmls" in dry_stdout
    assert dry_stderr == ""

    monkeypatch.setattr(sleuthkit, "run_cmd", lambda cmd, timeout=60: _result(stdout="partition table"))
    rc, stdout, stderr = sleuthkit.run_mmls({"image": str(image)})
    assert rc == 0
    assert "partition" in stdout
    assert stderr == ""

    monkeypatch.setattr(sleuthkit, "which", lambda name: None)
    rc, stdout, stderr = sleuthkit.run_mmls({})
    assert rc == 0
    assert "TOOL MISSING" in stderr


def test_volatility_wrapper_uses_cli_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(volatility, "which", lambda name: "/usr/bin/volatility3" if name == "volatility3" else None)
    monkeypatch.setattr(volatility.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(volatility, "run_cmd", lambda cmd, timeout=30: _result(stdout="Volatility 3.0"))

    assert volatility.available() is True
    assert volatility.version() == "Volatility 3.0"
    assert volatility.requirements()

    dry_rc, dry_stdout, dry_stderr = volatility.run_pslist({"dry_run": True})
    assert dry_rc == 0
    assert "volatility3" in dry_stdout
    assert dry_stderr == ""

    monkeypatch.setattr(volatility, "run_cmd", lambda cmd, timeout=60: _result(stdout="pslist help"))
    rc, stdout, stderr = volatility.run_pslist({})
    assert rc == 0
    assert stdout


def test_autopsy_wrapper_returns_guidance(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    launcher = tmp_path / "autopsy"
    launcher.write_text("#!/bin/sh")
    monkeypatch.setattr(autopsy, "which", lambda name: str(launcher) if name == "autopsy" else None)

    dry_rc, dry_stdout, dry_stderr = autopsy.run_headless_hint({"dry_run": True})
    assert dry_rc == 0
    assert dry_stdout == str(launcher)
    assert dry_stderr == ""

    rc, stdout, stderr = autopsy.run_headless_hint({})
    assert rc == 0
    assert "Autopsy is typically executed" in stderr

    monkeypatch.setattr(autopsy, "which", lambda name: None)
    rc, stdout, stderr = autopsy.run_headless_hint({"dry_run": True})
    assert rc == 0
    assert "TOOL MISSING" in stderr


def test_plaso_wrapper_detects_binaries(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(plaso, "which", lambda name: "/usr/bin/log2timeline.py" if name == "log2timeline.py" else None)
    monkeypatch.setattr(plaso, "run_cmd", lambda cmd, timeout=30: _result(stdout="plaso 20240101"))

    assert plaso.available() is True
    assert plaso.version() == "plaso 20240101"

    dry_rc, dry_stdout, dry_stderr = plaso.run_log2timeline({"dry_run": True})
    assert dry_rc == 0
    assert "log2timeline" in dry_stdout
    assert dry_stderr == ""

    source = tmp_path / "logs"
    source.write_text("dummy")
    rc, stdout, stderr = plaso.run_log2timeline({"source": str(source)})
    assert rc == 0
    assert "SAFEGUARD" in stderr

    monkeypatch.setattr(plaso, "which", lambda name: None)
    rc, stdout, stderr = plaso.run_log2timeline({})
    assert rc == 0
    assert "TOOL MISSING" in stderr


def test_bulk_extractor_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bulk_extractor, "which", lambda name: "/usr/bin/bulk_extractor" if name == "bulk_extractor" else None)
    monkeypatch.setattr(bulk_extractor, "run_cmd", lambda cmd, timeout=30: _result(stdout="bulk_extractor 2.0"))

    assert bulk_extractor.available() is True
    assert bulk_extractor.version() == "bulk_extractor 2.0"

    dry_rc, dry_stdout, dry_stderr = bulk_extractor.run_version({"dry_run": True})
    assert dry_rc == 0
    assert "bulk_extractor" in dry_stdout
    assert dry_stderr == ""

    rc, stdout, stderr = bulk_extractor.run_version({})
    assert rc == 0
    assert "bulk_extractor 2.0" in stdout

    monkeypatch.setattr(bulk_extractor, "which", lambda name: None)
    rc, stdout, stderr = bulk_extractor.run_version({})
    assert rc == 0
    assert "TOOL MISSING" in stderr


def test_yara_wrapper_protects_execution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(yara, "which", lambda name: "/usr/bin/yara" if name == "yara" else None)
    monkeypatch.setattr(yara, "run_cmd", lambda cmd, timeout=30: _result(stdout="yara 4.5.0"))

    assert yara.available() is True
    assert yara.version() == "yara 4.5.0"

    rules = tmp_path / "rules.yar"
    rules.write_text("rule dummy { condition: true }")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"abc")

    dry_rc, dry_stdout, dry_stderr = yara.run_scan({
        "dry_run": True,
        "rules": str(rules),
        "target": str(target),
        "recursive": True,
    })
    assert dry_rc == 0
    assert "yara" in dry_stdout
    assert "-r" in dry_stdout
    assert dry_stderr == ""

    rc, stdout, stderr = yara.run_scan({"rules": str(rules), "target": str(target)})
    assert rc == 0
    assert "SAFEGUARD" in stderr

    rc, stdout, stderr = yara.run_scan({
        "rules": str(rules),
        "target": str(target),
        "allow_execution": True,
    })
    assert rc == 0
    assert stdout in {"", "yara 4.5.0"}

    monkeypatch.setattr(yara, "which", lambda name: None)
    rc, stdout, stderr = yara.run_scan({})
    assert rc == 0
    assert "TOOL MISSING" in stderr
