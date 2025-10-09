from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Dict, Optional

from click.testing import CliRunner

from forensic.cli import cli
from forensic.core.evidence import EvidenceType
from forensic.core.framework import ForensicFramework
from forensic.modules.analysis.network import NetworkAnalysisModule
from forensic.modules.reporting.generator import ReportGenerator
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
            analysis_result = framework.execute_module("network", params=analysis_params)
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
