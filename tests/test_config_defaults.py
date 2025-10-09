from __future__ import annotations

from pathlib import Path

import pytest

from forensic.modules.acquisition.network_capture import NetworkCaptureModule
from forensic.modules.analysis.network import NetworkAnalysisModule
from forensic.modules.analysis.timeline import TimelineModule
from forensic.modules.reporting.generator import ReportGenerator


@pytest.fixture()
def temp_case_dir(tmp_path: Path) -> Path:
    return tmp_path


def test_network_capture_uses_yaml_defaults(temp_case_dir: Path) -> None:
    config = {
        "network": {
            "default_bpf": "port 80",
            "default_interface": "eth1",
            "default_duration": 123,
            "default_tool": "dumpcap",
        }
    }
    module = NetworkCaptureModule(case_dir=temp_case_dir, config=config)

    params: dict[str, object] = {}
    assert module.validate_params(params) is True
    assert params["bpf"] == "port 80"
    assert params["interface"] == "eth1"
    assert params["duration"] == 123
    assert params["tool"] == "dumpcap"


def test_network_capture_cli_precedence(temp_case_dir: Path) -> None:
    config = {"network": {"default_bpf": "port 80"}}
    module = NetworkCaptureModule(case_dir=temp_case_dir, config=config)

    params = {"bpf": "port 53"}
    assert module.validate_params(params) is True
    assert params["bpf"] == "port 53"


def test_network_analysis_uses_configured_pcap_json(temp_case_dir: Path) -> None:
    pcap_json = temp_case_dir / "capture.json"
    pcap_json.write_text("{}", encoding="utf-8")

    config = {"network": {"pcap_json": str(pcap_json)}}
    module = NetworkAnalysisModule(case_dir=temp_case_dir, config=config)

    params: dict[str, object] = {}
    assert module.validate_params(params) is True
    assert params["pcap_json"] == str(pcap_json)


def test_timeline_timezone_resolves_from_config(temp_case_dir: Path) -> None:
    module = TimelineModule(
        case_dir=temp_case_dir,
        config={"timeline": {"timezone": "Europe/Berlin"}},
    )

    assert module._effective_timezone({}) == "Europe/Berlin"
    assert module._effective_timezone({"timezone": "Asia/Tokyo"}) == "Asia/Tokyo"


def test_report_generator_respects_output_dir(temp_case_dir: Path) -> None:
    config = {"reports": {"output_dir": "custom_reports"}}
    module = ReportGenerator(case_dir=temp_case_dir, config=config)

    expected_path = temp_case_dir / "custom_reports"
    assert module.output_dir == expected_path
    assert expected_path.exists()
