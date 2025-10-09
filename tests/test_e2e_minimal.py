from __future__ import annotations

import io
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from forensic.cli import cli
from forensic.core import config as config_module
from forensic.core.evidence import EvidenceType
from forensic.core.framework import ForensicFramework
from forensic.modules.analysis.network import NetworkAnalysisModule
from forensic.modules.reporting.generator import ReportGenerator
from forensic.utils import cmd as cmd_utils
from forensic.utils import hashing
from forensic.utils import io as io_utils
from forensic.utils import paths as paths_utils
from forensic.utils import timefmt
from tests.utils import invoke_pcap_synth, redirect_stdin


def test_minimal_end_to_end_flow(tmp_path: Path) -> None:
    """Run a minimal diagnostics → analysis → report workflow."""

    runner = CliRunner()
    workspace = tmp_path / ".cases"

    diagnostics = runner.invoke(cli, ["--workspace", str(workspace), "diagnostics"])
    assert diagnostics.exit_code == 0, diagnostics.output

    init_result = runner.invoke(
        cli,
        [
            "--workspace",
            str(workspace),
            "case",
            "init",
            "demo",
            "--name",
            "Demo Case",
            "--investigator",
            "Case Tester",
        ],
    )
    assert init_result.exit_code == 0, init_result.output

    framework = ForensicFramework(workspace=workspace)
    framework.register_module("network", NetworkAnalysisModule)
    case = framework.load_case("demo")

    fixtures_dir = tmp_path / "fixtures"
    pcap_path, synth_stdout = invoke_pcap_synth(fixtures_dir)

    analysis_params: Dict[str, str]
    evidence_source: Path
    analysis_input_payload: Optional[str]
    if pcap_path is not None:
        analysis_params = {"pcap": str(pcap_path)}
        evidence_source = pcap_path
        analysis_input_payload = None
    else:
        assert synth_stdout, "Synthesizer returned no fixture data"
        payload = json.loads(synth_stdout)
        json_fixture = fixtures_dir / "minimal_pcap.json"
        json_payload = json.dumps(payload, indent=2, sort_keys=True)
        json_fixture.write_text(json_payload, encoding="utf-8")
        analysis_params = {"pcap_json": "-"}
        evidence_source = json_fixture
        analysis_input_payload = json_payload

    framework.add_evidence(
        EvidenceType.NETWORK,
        evidence_source,
        description="Synthesised network fixture",
    )

    if analysis_params.get("pcap_json") == "-":
        assert analysis_input_payload is not None
        with redirect_stdin(io.StringIO(analysis_input_payload)):
            analysis_result = framework.execute_module(
                "network", params=analysis_params
            )
    else:
        analysis_result = framework.execute_module("network", params=analysis_params)
    assert analysis_result.status == "success"
    assert analysis_result.output_path is not None
    assert analysis_result.output_path.exists()
    metadata = analysis_result.metadata
    if analysis_params.get("pcap_json") == "-":
        assert metadata.get("pcap_json_mode") is True
        assert metadata.get("pcap_json_source")
    elif metadata.get("pcap_extra_available"):
        assert metadata["pcap_extra_available"] is True
    else:
        assert metadata.get("fallback_parser") == "builtin"

    payload = json.loads(analysis_result.output_path.read_text(encoding="utf-8"))
    assert payload["flows"], "no network flows were extracted"
    queries = payload["dns"]["queries"]
    assert queries, "expected DNS queries in minimal fixture"
    assert any("example.com" in (q.get("query") or "") for q in queries)

    report_module = ReportGenerator(case_dir=case.case_dir, config=framework.config)
    report_result = report_module.run(None, {"format": "html"})

    assert report_result.status == "success"
    assert report_result.output_path is not None
    assert report_result.output_path.exists()

    html_report = report_result.output_path.read_text(encoding="utf-8")
    assert "<h1>Forensic Investigation Report</h1>" in html_report
    if "Network Insights" in html_report:
        assert "Network Insights" in html_report
    else:
        assert 'data-marker="report-fallback"' in html_report

    artifacts_root = case.case_dir / "analysis" / "network"
    output_candidates = list(artifacts_root.rglob("network.json"))
    assert output_candidates, "network artefact missing"
    output_file = output_candidates[0]
    artefact_payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert "flows" in artefact_payload
    assert "dns" in artefact_payload
    assert "http" in artefact_payload

    reports_root = case.case_dir / "reports"
    assert reports_root in report_result.output_path.parents

    # Exercise lightweight utility helpers to improve coverage of critical modules.
    utility_root = workspace / "utility-checks"
    resolved_workspace = paths_utils.resolve_workspace(workspace, "utility-checks")
    assert resolved_workspace == utility_root
    sample_text = resolved_workspace / "sample.txt"
    io_utils.write_text(sample_text, "utility data")
    assert io_utils.read_text(sample_text) == "utility data"
    assert io_utils.read_text(resolved_workspace / "missing.txt") == ""

    json_target = resolved_workspace / "data.json"
    io_utils.write_json(json_target, {"b": 1, "a": 2})
    resolved_paths = list(
        paths_utils.resolve_config_paths(
            resolved_workspace, [sample_text.name, json_target.name, "missing.json"]
        )
    )
    assert resolved_paths == [sample_text, json_target]

    optional_result = paths_utils.optional_path(str(json_target))
    assert optional_result == json_target
    assert paths_utils.optional_path(None) is None

    python_tool = Path(sys.executable).name
    resolved_python = cmd_utils.ensure_tool(python_tool)
    assert resolved_python.endswith(python_tool)
    command_result = cmd_utils.run(
        [Path(resolved_python), "-c", "print('cmd util coverage')"]
    )
    assert "cmd util coverage" in command_result.stdout
    with pytest.raises(TypeError):
        cmd_utils.run("not a sequence")
    with pytest.raises(cmd_utils.CommandError):
        cmd_utils.ensure_tool("forensic-tool-that-should-not-exist")

    hash_target = resolved_workspace / "hash-target.txt"
    io_utils.write_text(hash_target, "hash me")
    hashes = hashing.compute_hashes(hash_target, ["md5", "sha1"])
    assert set(hashes) == {"md5", "sha1"}

    config_dir = resolved_workspace / "config-demo"
    config_dir.mkdir()
    config_file = config_dir / "framework.yaml"
    config_file.write_text("log_level: DEBUG\nmax_workers: 3", encoding="utf-8")

    assert config_module.load_yaml(config_dir / "missing.yaml") == {}
    original_yaml = config_module.yaml
    with pytest.warns(RuntimeWarning):
        assert config_module.load_yaml(config_file) == {}

    error_yaml = SimpleNamespace(safe_load=lambda handle: [1, 2, 3])
    config_module.yaml = error_yaml
    with pytest.raises(TypeError):
        config_module.load_yaml(config_file)

    stub_yaml = SimpleNamespace(
        safe_load=lambda handle: {
            line.split(":", 1)[0].strip(): line.split(":", 1)[1].strip()
            for line in handle.read().splitlines()
            if ":" in line
        }
    )
    config_module.yaml = stub_yaml
    os.environ["FORENSIC_MAX_WORKERS"] = "6"
    os.environ["FORENSIC_ENABLE_COC"] = "FALSE"
    os.environ["FORENSIC_CONFIG_DIR"] = str(config_dir)
    try:
        loaded = config_module.load_yaml(config_file)
        assert loaded["log_level"] == "DEBUG"
        merged_config = config_module.merge_dicts(
            {"network": {"interface": "eth0", "timeout": 3}},
            {"network": {"timeout": 10}},
        )
        assert merged_config["network"]["timeout"] == 10
        cfg = config_module.get_config(
            config_root=None, overrides={"workspace_name": "demo-case"}
        )
        resolved_root = config_module._resolve_config_root(None)
        assert resolved_root == config_dir
    finally:
        config_module.yaml = original_yaml
        os.environ.pop("FORENSIC_MAX_WORKERS", None)
        os.environ.pop("FORENSIC_ENABLE_COC", None)
        os.environ.pop("FORENSIC_CONFIG_DIR", None)

    assert cfg.log_level == "DEBUG"
    assert cfg.max_workers == 6
    assert cfg.enable_coc is False
    assert cfg.workspace_name == "demo-case"
    assert cfg.as_dict()["log_level"] == "DEBUG"

    naive_timestamp = timefmt.to_iso(datetime(2024, 1, 1, 12, 0, 0))
    aware_timestamp = timefmt.to_iso(datetime(2024, 1, 1, 14, 0, 0, tzinfo=timezone.utc))
    current_timestamp = timefmt.utcnow_iso()
    assert timefmt.to_iso(None) is None
    assert naive_timestamp == "2024-01-01T12:00:00Z"
    assert aware_timestamp == "2024-01-01T14:00:00Z"
    assert current_timestamp.endswith("Z")

    hashes = hashing.compute_hashes(sample_text, ["md5", "sha1", "sha256"])
    assert hashes["sha256"]
    with pytest.raises(ValueError):
        hashing.compute_stream_hash(io.BytesIO(b"x"), chunk_size=0)
    with pytest.raises(ValueError):
        hashing.compute_stream_hash(io.BytesIO(b"x"), algorithm="sha512")

    python_exec = sys.executable
    resolved_python = cmd_utils.ensure_tool(python_exec)
    assert Path(resolved_python).exists()
    run_result = cmd_utils.run([python_exec, "-c", "print('ok')"], timeout=10)
    assert run_result.stdout.strip() == "ok"
    with pytest.raises(TypeError):
        cmd_utils.run("echo invalid")
    with pytest.raises(ValueError):
        cmd_utils.run([], timeout=10)
