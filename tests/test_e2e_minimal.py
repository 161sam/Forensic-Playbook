from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from forensic.cli import cli
from forensic.core.evidence import EvidenceType
from forensic.core.framework import ForensicFramework
from forensic.modules.analysis.network import NetworkAnalysisModule
from forensic.modules.reporting.generator import ReportGenerator
from tests.data.pcap import write_minimal_pcap


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

    pcap_path = write_minimal_pcap(tmp_path / "fixtures" / "minimal.pcap")

    framework.add_evidence(
        EvidenceType.NETWORK,
        pcap_path,
        description="Minimal PCAP fixture",
    )

    analysis_result = framework.execute_module(
        "network", params={"pcap": str(pcap_path)}
    )
    assert analysis_result.status == "success"
    assert analysis_result.output_path is not None
    assert analysis_result.output_path.exists()
    if analysis_result.metadata.get("pcap_extra_available"):
        assert analysis_result.metadata["pcap_extra_available"] is True
    else:
        assert analysis_result.metadata.get("fallback_parser") == "builtin"

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
    assert any(artifacts_root.rglob("network.json")), "network artefact missing"

    reports_root = case.case_dir / "reports"
    assert reports_root in report_result.output_path.parents
