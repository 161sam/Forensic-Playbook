#!/usr/bin/env python3
"""Execute the minimal end-to-end flow used in CI."""
from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple


ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from click.testing import CliRunner

from forensic.cli import cli
from forensic.core.evidence import EvidenceType
from forensic.core.framework import ForensicFramework
from forensic.modules.analysis.network import NetworkAnalysisModule
from forensic.modules.reporting.generator import ReportGenerator
from tests.utils import invoke_pcap_synth, redirect_stdin


def _synthesise_network_fixture(
    out_dir: Path,
) -> Tuple[Path, Dict[str, str], Optional[str]]:
    """Generate the network fixture and return the source path, params and STDIN."""

    pcap_path, synth_stdout = invoke_pcap_synth(out_dir)
    if pcap_path is not None:
        print(
            f"[e2e] Synthesizer produced PCAP fixture at {pcap_path}",
            flush=True,
        )
        return pcap_path, {"pcap": str(pcap_path)}, None

    if not synth_stdout:
        raise RuntimeError("Synthesizer returned no fixture data")

    print(
        "[e2e] Synthesizer returned JSON fallback; using --pcap-json - via STDIN",
        flush=True,
    )

    payload = json.loads(synth_stdout)
    json_fixture = out_dir / "minimal_pcap.json"
    json_payload = json.dumps(payload, indent=2, sort_keys=True)
    json_fixture.write_text(json_payload, encoding="utf-8")
    return json_fixture, {"pcap_json": "-"}, json_payload


def run_minimal_flow(
    workspace: Path,
    report_path: Path,
    *,
    generate_report: bool = True,
) -> Path:
    """Run diagnostics → network analysis and optionally generate a report."""

    runner = CliRunner()
    workspace.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    diagnostics = runner.invoke(cli, ["--workspace", str(workspace), "diagnostics"])
    if diagnostics.exit_code != 0:
        raise RuntimeError(f"Diagnostics failed: {diagnostics.output}")

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
            "CI Runner",
            "--force",
        ],
    )
    if init_result.exit_code != 0:
        raise RuntimeError(f"Case init failed: {init_result.output}")

    framework = ForensicFramework(workspace=workspace)
    framework.register_module("network", NetworkAnalysisModule)
    case = framework.load_case("demo")

    fixtures_dir = workspace / "fixtures"
    fixture_path, analysis_params, stdin_payload = _synthesise_network_fixture(
        fixtures_dir
    )

    framework.add_evidence(
        EvidenceType.NETWORK,
        fixture_path,
        description="Synthesised network fixture",
    )

    if analysis_params.get("pcap_json") == "-" and stdin_payload is not None:
        with redirect_stdin(io.StringIO(stdin_payload)):
            analysis_result = framework.execute_module("network", params=analysis_params)
    else:
        analysis_result = framework.execute_module("network", params=analysis_params)
    if analysis_result.status != "success":
        raise RuntimeError(
            "Network analysis failed:",
            f" {analysis_result.status} | {analysis_result.errors}"
        )

    if not generate_report:
        return report_path

    report_module = ReportGenerator(case_dir=case.case_dir, config=framework.config)
    report_result = report_module.run(
        None, {"format": "html", "output_file": str(report_path)}
    )
    if report_result.status != "success":
        raise RuntimeError(
            "Report generation failed:",
            f" {report_result.status} | {report_result.errors}"
        )

    if (
        report_result.output_path is None
        or not Path(report_result.output_path).exists()
    ):
        raise RuntimeError("Report was not written to disk")

    return Path(report_result.output_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("out/workspace"),
        help="Workspace directory for the generated case",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("out/report.html"),
        help="Destination for the generated HTML report",
    )
    parser.add_argument(
        "--skip-report",
        action="store_true",
        help="Prepare the workspace without generating an HTML report",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_path = run_minimal_flow(
        args.workspace, args.report, generate_report=not args.skip_report
    )

    if args.skip_report:
        print(
            "Minimal flow completed without generating a report (skip requested)."
        )
    else:
        print(f"Report generated at: {output_path}")



if __name__ == "__main__":
    main()
