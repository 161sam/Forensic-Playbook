"""Regression tests covering guarded module behaviours.

This suite exercises the hardened modules that were promoted from
MVP to guarded status.  The focus is on guard friendliness, dry-run
handling and configuration precedence without depending on external
tooling or binary fixtures.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Dict

import pytest
from click.testing import CliRunner

from forensic.modules.acquisition.live_response import LiveResponseModule
from forensic.modules.acquisition.network_capture import NetworkCaptureModule
from forensic.cli import cli
from forensic.modules.analysis.network import NetworkAnalysisModule
from forensic.modules.reporting.generator import ReportGenerator
from forensic.modules.triage.persistence import PersistenceModule
from forensic.modules.triage.quick_triage import QuickTriageModule
from forensic.modules.triage.system_info import SystemInfoModule


@pytest.fixture
def guarded_case(tmp_path: Path) -> Path:
    """Return a case directory with the expected workspace hierarchy."""

    workspace = tmp_path / "workspace"
    case_dir = workspace / "cases" / "demo"
    for relative in (
        "analysis",
        "acq",
        "triage",
        "reports",
        "meta",
    ):
        (case_dir / relative).mkdir(parents=True, exist_ok=True)
    return case_dir


def test_live_response_missing_tool_guard(guarded_case: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = LiveResponseModule(case_dir=guarded_case, config={})
    monkeypatch.setattr(module, "_verify_tool", lambda tool: False)

    result = module.run(None, {"commands": ["uname -a"]})

    assert result.status == "partial"
    assert result.metadata.get("missing_tools") == ["uname"]
    guard_meta = result.metadata.get("guard", {})
    assert "Install the missing tools" in " ".join(guard_meta.get("hints", []))
    planned_dir = guarded_case / "acq" / "live"
    assert not planned_dir.exists()


def test_live_response_dry_run_creates_no_artifacts(
    guarded_case: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = LiveResponseModule(case_dir=guarded_case, config={})
    monkeypatch.setattr(module, "_verify_tool", lambda tool: True)

    result = module.run(None, {"dry_run": True, "commands": ["uname -a"]})

    assert result.status == "success"
    metadata = result.metadata
    assert metadata.get("dry_run") is True
    planned_directory_text = metadata.get("planned_directory")
    assert planned_directory_text is not None
    planned_directory = Path(planned_directory_text)
    assert not planned_directory.exists()


def test_network_capture_uses_config_defaults(guarded_case: Path) -> None:
    config: Dict[str, Dict[str, Dict[str, object]]] = {
        "modules": {
            "network": {"default_bpf": "port 443"},
            "network_capture": {"interface": "eth1", "duration": 180},
        }
    }
    module = NetworkCaptureModule(case_dir=guarded_case, config=config)
    params: Dict[str, object] = {}

    assert module.validate_params(params) is True
    assert params["bpf"] == "port 443"
    assert params["interface"] == "eth1"
    assert params["duration"] == 180
    assert module._param_sources["bpf"] == "config"
    assert module._param_sources["interface"] == "config"


def test_network_capture_guard_when_no_tool_available(
    guarded_case: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = NetworkCaptureModule(case_dir=guarded_case, config={})
    monkeypatch.setattr(module, "_verify_tool", lambda tool: False)

    result = module.run(None, {"enable_live_capture": True})

    assert result.status == "skipped"
    missing = result.metadata.get("missing_tools")
    assert missing == ["dumpcap", "tcpdump"]
    guard_meta = result.metadata.get("guard", {})
    assert "Install dumpcap or tcpdump" in " ".join(guard_meta.get("hints", []))


def test_network_analysis_config_defaults(guarded_case: Path) -> None:
    config = {
        "modules": {
            "network_analysis": {
                "default_pcap_json": "-",
                "output_filename": "custom-network.json",
            }
        }
    }
    module = NetworkAnalysisModule(case_dir=guarded_case, config=config)
    params: Dict[str, object] = {}

    assert module.validate_params(params) is True
    assert params["pcap_json"] == "-"
    assert module._param_sources["pcap_json"] == "config"
    assert params["dry_run"] is False


def test_network_analysis_dry_run_has_no_output(guarded_case: Path) -> None:
    module = NetworkAnalysisModule(case_dir=guarded_case, config={})

    result = module.run(None, {"pcap_json": "-", "dry_run": True})

    assert result.status == "success"
    metadata = result.metadata
    assert metadata.get("dry_run") is True
    planned_output_text = metadata.get("planned_output_file")
    assert planned_output_text is not None
    planned_output = Path(planned_output_text)
    assert not planned_output.exists()


def test_report_generator_dry_run_plans_output(guarded_case: Path) -> None:
    module = ReportGenerator(case_dir=guarded_case, config={})

    result = module.run(None, {"fmt": "html", "dry_run": True})

    assert result.status == "success"
    metadata = result.metadata
    assert metadata.get("dry_run") is True
    planned = metadata.get("planned_output")
    assert planned is not None
    assert planned.endswith(".html")
    assert not Path(planned).exists()


def test_persistence_dry_run_uses_configured_paths(guarded_case: Path) -> None:
    config = {
        "modules": {
            "persistence": {"paths": {"cron": ["/tmp/cron.d", "/etc/cron.d"]}},
        }
    }
    module = PersistenceModule(case_dir=guarded_case, config=config)
    params: Dict[str, object] = {}

    assert module.validate_params(params) is True
    assert "cron" in params["paths"]

    result = module.run(None, {"dry_run": True, "paths": params["paths"]})

    assert result.status == "success"
    metadata = result.metadata
    assert "cron" in metadata.get("paths", {})
    planned_directory_text = metadata.get("planned_directory")
    assert planned_directory_text is not None
    planned_directory = Path(planned_directory_text)
    assert not planned_directory.exists()


def test_system_info_config_fields_and_dry_run(guarded_case: Path) -> None:
    config = {
        "modules": {"system_info": {"fields": ["hostname", "timezone"]}}
    }
    module = SystemInfoModule(case_dir=guarded_case, config=config)
    params: Dict[str, object] = {}

    assert module.validate_params(params) is True
    assert params["fields"] == ["hostname", "timezone"]

    result = module.run(None, {"fields": params["fields"], "dry_run": True})

    assert result.status == "success"
    metadata = result.metadata
    assert metadata.get("fields") == ["hostname", "timezone"]
    planned_directory_text = metadata.get("planned_directory")
    assert planned_directory_text is not None
    planned_directory = Path(planned_directory_text)
    assert not planned_directory.exists()


def test_quick_triage_dry_run_respects_configured_target(
    guarded_case: Path, tmp_path: Path
) -> None:
    target = tmp_path / "mountpoint"
    target.mkdir()
    (target / "bin").mkdir()

    config = {
        "modules": {
            "quick_triage": {
                "target": str(target),
                "checks": {"suid_sgid": {"enabled": False}},
            }
        }
    }

    module = QuickTriageModule(case_dir=guarded_case, config=config)
    params: Dict[str, object] = {}

    assert module.validate_params(params) is True
    assert params["target"] == target

    result = module.run(None, {"target": target, "dry_run": True})

    assert result.status == "success"
    metadata = result.metadata
    assert metadata.get("target") == str(target)
    planned_directory_text = metadata.get("planned_directory")
    assert planned_directory_text is not None
    planned_directory = Path(planned_directory_text)
    assert not planned_directory.exists()



def test_diagnostics_lists_guarded_wrappers(tmp_path: Path) -> None:
    runner = CliRunner()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    result = runner.invoke(cli, ["--workspace", str(workspace), "diagnostics"])
    assert result.exit_code == 0, result.output
    output = result.output
    assert "Guarded tool wrappers:" in output
    assert "Module integrations:" in output
    for name in ["Sleuthkit", "Plaso", "Volatility", "YARA", "bulk_extractor", "Autopsy"]:
        assert re.search(rf"{name}:", output)
