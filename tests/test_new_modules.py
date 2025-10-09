import importlib.util
import json
import pathlib
from pathlib import Path

import pytest
from click.testing import CliRunner

from forensic.core.config import FrameworkConfig, get_config
from forensic.modules.acquisition.live_response import LiveResponseModule
from forensic.modules.acquisition.memory_dump import MemoryDumpModule
from forensic.modules.acquisition.network_capture import NetworkCaptureModule
from forensic.modules.analysis.malware import MalwareAnalysisModule
from forensic.modules.reporting.exporter import export_report
from forensic.modules.triage.persistence import PersistenceModule
from forensic.modules.triage.system_info import SystemInfoModule


def _load_cli():
    cli_path = Path(__file__).resolve().parents[1] / "scripts" / "forensic-cli.py"
    spec = importlib.util.spec_from_file_location("forensic_cli", cli_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)  # type: ignore[assignment]
    return module.cli


@pytest.fixture()
def temp_case(tmp_path):
    case_dir = tmp_path / "case"
    (case_dir / "analysis").mkdir(parents=True)
    (case_dir / "reports").mkdir()
    (case_dir / "evidence").mkdir()
    return case_dir


def test_get_config_defaults(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_CONFIG_DIR", raising=False)
    cfg = get_config(config_root=tmp_path)
    assert isinstance(cfg, FrameworkConfig)
    assert cfg.log_level == "INFO"
    assert cfg.timezone == "UTC"


def test_get_config_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_LOG_LEVEL", "DEBUG")
    cfg = get_config(config_root=tmp_path)
    assert cfg.log_level == "DEBUG"


def test_memory_dump_guard(temp_case, monkeypatch):
    module = MemoryDumpModule(case_dir=temp_case, config={})
    monkeypatch.setattr(module, "_verify_tool", lambda tool: False)
    result = module.run(None, {"output": temp_case / "analysis" / "mem.raw"})
    assert result.status == "skipped"
    assert result.errors


def test_network_capture_dry_run(temp_case, monkeypatch):
    module = NetworkCaptureModule(case_dir=temp_case, config={})
    monkeypatch.setattr(module, "_verify_tool", lambda tool: True)
    result = module.run(None, {"dry_run": True, "tool": "tcpdump"})
    assert result.status == "success"
    assert any(f["type"] == "dry_run" for f in result.findings)


def test_live_response_handles_missing_tools(temp_case, monkeypatch):
    module = LiveResponseModule(case_dir=temp_case, config={})
    monkeypatch.setattr(module, "_verify_tool", lambda tool: False)
    result = module.run(None, {})
    assert result.status == "partial"
    assert result.errors


def test_malware_module_hash_only(tmp_path, temp_case, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    module = MalwareAnalysisModule(case_dir=temp_case, config={})
    monkeypatch.setattr(module, "_verify_tool", lambda tool: False)
    result = module.run(None, {"target": sample})
    assert result.metadata["hash_sha256"]
    assert result.status == "partial"


def test_system_info_outputs_json(temp_case):
    module = SystemInfoModule(case_dir=temp_case, config={})
    result = module.run(None, {})
    assert result.output_path is not None
    assert result.output_path.exists()
    assert result.output_path.name == "system.json"
    assert result.output_path.parent.parent.name == "system_info"
    data = json.loads(result.output_path.read_text())
    assert "hostname" in data
    assert "os" in data
    assert data["fields"]


def test_system_info_dry_run(temp_case):
    module = SystemInfoModule(case_dir=temp_case, config={})
    result = module.run(None, {"dry_run": True})
    assert result.status == "success"
    assert result.output_path is None
    assert result.metadata.get("dry_run") is True
    artifacts = list((temp_case / "triage").rglob("system.json"))
    assert not artifacts


def test_persistence_handles_missing_paths(temp_case, monkeypatch):
    module = PersistenceModule(case_dir=temp_case, config={})
    monkeypatch.setattr(pathlib.Path, "is_file", lambda self: False)
    monkeypatch.setattr(pathlib.Path, "is_dir", lambda self: False)
    monkeypatch.setattr(
        pathlib.Path, "mkdir", lambda self, parents=False, exist_ok=False: None
    )
    result = module.run(None, {})
    assert result.status == "partial"


def test_exporter_roundtrip(tmp_path):
    data = {"case": {"id": "CASE_TEST"}}
    json_path = tmp_path / "report.json"
    md_path = tmp_path / "report.md"
    export_report(data, "json", json_path)
    export_report(data, "markdown", md_path)
    assert json.loads(json_path.read_text())["case"]["id"] == "CASE_TEST"
    assert md_path.read_text().startswith("# Report")


def test_cli_module_list_handles_skips(monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr("shutil.which", lambda tool: None)
    cli = _load_cli()
    result = runner.invoke(cli, ["module", "list"])
    assert result.exit_code == 0
    assert "Unavailable modules" in result.output
