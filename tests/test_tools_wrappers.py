from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic.tools import autopsy, bulk_extractor, plaso, sleuthkit, volatility, yara


def test_sleuthkit_version_and_availability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sleuthkit, "_first_available", lambda _: "tsk_version")
    monkeypatch.setattr(sleuthkit, "_execute", lambda *args, **kwargs: (0, "TSK 4.12", ""))

    assert sleuthkit.available() is True
    assert sleuthkit.version() == "TSK 4.12"

    monkeypatch.setattr(sleuthkit, "_first_available", lambda _: "mmls")
    monkeypatch.setattr(sleuthkit, "_execute", lambda *args, **kwargs: (1, "", "error"))
    assert sleuthkit.version() is None

    monkeypatch.setattr(sleuthkit, "_first_available", lambda _: None)
    assert sleuthkit.available() is False


def test_sleuthkit_dry_run_helpers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sleuthkit, "_first_available", lambda candidates: candidates[0])

    code, stdout, stderr = sleuthkit.run_mmls_version({"dry_run": True})
    assert code == 0
    assert "mmls" in stdout
    assert stderr == ""

    image = tmp_path / "disk.img"
    image.write_bytes(b"TSK")

    code, stdout, stderr = sleuthkit.run_fls_listing(
        {"image": str(image), "dry_run": True, "recursive": False}
    )
    assert code == 0
    assert "fls" in stdout
    assert str(image) in stdout


def test_volatility_version_prefers_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(volatility, "_first_available", lambda _: "volatility3")
    monkeypatch.setattr(
        volatility, "_execute", lambda *args, **kwargs: (0, "Volatility 3.0", "")
    )
    assert volatility.version() == "Volatility 3.0"

    monkeypatch.setattr(volatility, "_first_available", lambda _: None)
    monkeypatch.setattr(volatility, "_module_available", lambda: True)
    monkeypatch.setattr(
        volatility.importlib,
        "import_module",
        lambda name: SimpleNamespace(__version__="3.1"),
    )
    assert volatility.version() == "3.1"


def test_volatility_run_pslist_dry_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(volatility, "_first_available", lambda _: "volatility3")
    monkeypatch.setattr(volatility, "_module_available", lambda: False)

    memory = tmp_path / "mem.raw"
    memory.write_bytes(b"vol")

    code, stdout, stderr = volatility.run_pslist(
        {"memory": str(memory), "dry_run": True, "limit": 5}
    )
    assert code == 0
    assert "volatility3" in stdout
    assert "windows.pslist" in stdout
    assert stderr == ""

    code, stdout, stderr = volatility.run_info({"dry_run": True})
    assert code == 0
    assert "--info" in stdout


def test_autopsy_launch_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(autopsy, "which", lambda name: "/usr/bin/autopsy" if name == "autopsy" else None)
    assert autopsy.available() is True
    code, stdout, stderr = autopsy.run_launch_hint({"dry_run": True})
    assert code == 0
    assert "Autopsy" in stdout
    assert stderr == ""

    monkeypatch.setattr(autopsy, "which", lambda name: None)
    assert autopsy.available() is False
    code, stdout, stderr = autopsy.run_launch_hint({})
    assert "TOOL MISSING" in stderr


def test_plaso_wrappers(monkeypatch: pytest.MonkeyPatch) -> None:
    original_execute = plaso._execute

    monkeypatch.setattr(plaso, "_first_available", lambda candidates: candidates[0])
    monkeypatch.setattr(plaso, "_execute", lambda *args, **kwargs: (0, "Plaso 20240101", ""))
    assert plaso.version() == "Plaso 20240101"

    monkeypatch.setattr(plaso, "_execute", original_execute)

    code, stdout, stderr = plaso.run_log2timeline_version({"dry_run": True})
    assert code == 0
    assert "log2timeline.py" in stdout
    assert stderr == ""

    code, stdout, stderr = plaso.run_psort_version({"dry_run": True})
    assert code == 0
    assert "psort.py" in stdout


def test_bulk_extractor_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    original_execute = bulk_extractor._execute

    monkeypatch.setattr(bulk_extractor, "available", lambda: True)
    monkeypatch.setattr(
        bulk_extractor, "_execute", lambda *args, **kwargs: (0, "bulk_extractor 2.0", "")
    )
    assert bulk_extractor.version() == "bulk_extractor 2.0"

    monkeypatch.setattr(bulk_extractor, "available", lambda: False)
    assert bulk_extractor.version() is None

    monkeypatch.setattr(bulk_extractor, "available", lambda: True)
    monkeypatch.setattr(bulk_extractor, "_execute", original_execute)
    code, stdout, stderr = bulk_extractor.run_version({"dry_run": True})
    assert code == 0
    assert "bulk_extractor" in stdout
    assert stderr == ""


def test_yara_wrapper_dry_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    original_execute = yara._execute

    monkeypatch.setattr(yara, "available", lambda: True)
    monkeypatch.setattr(yara, "_execute", original_execute)

    code, stdout, stderr = yara.run_version({"dry_run": True})
    assert code == 0
    assert "yara" in stdout

    rule = tmp_path / "rule.yar"
    target = tmp_path / "target.bin"
    rule.write_text('rule demo { condition: true }', encoding="utf-8")
    target.write_bytes(b"demo")

    code, stdout, stderr = yara.run_scan(
        {"rule": str(rule), "target": str(target), "dry_run": True, "recursive": True}
    )
    assert code == 0
    assert "yara" in stdout
    assert "-r" in stdout
    assert stderr == ""

    monkeypatch.setattr(yara, "available", lambda: False)
    code, stdout, stderr = yara.run_scan({"rule": str(rule), "target": str(target)})
    assert "TOOL MISSING" in stderr
