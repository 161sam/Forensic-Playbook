#!/usr/bin/env python3
"""Execute the minimal end-to-end flow used in CI."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from typing import Callable

from click.testing import CliRunner

from forensic.cli import cli
from forensic.core.evidence import EvidenceType
from forensic.core.framework import ForensicFramework
from forensic.modules.analysis.network import NetworkAnalysisModule
from forensic.modules.reporting.generator import ReportGenerator


def _load_fixture_writer() -> Callable[[Path], Path]:
    """Load the ``write_minimal_pcap`` helper from the test fixtures."""

    fixture_path = Path("tests/data/pcap/__init__.py")
    spec = importlib.util.spec_from_file_location("tests.data.pcap", fixture_path)
    if spec is None or spec.loader is None:  # pragma: no cover - safety net
        raise RuntimeError("Unable to load minimal PCAP fixture helper")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    writer = getattr(module, "write_minimal_pcap", None)
    if writer is None:  # pragma: no cover - safety net
        raise RuntimeError("Fixture module did not expose write_minimal_pcap")
    return writer


def run_minimal_flow(workspace: Path, report_path: Path) -> Path:
    """Run diagnostics → network analysis → report generation."""

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

    fixture_writer = _load_fixture_writer()
    pcap_path = fixture_writer(workspace / "fixtures" / "minimal.pcap")

    framework.add_evidence(
        EvidenceType.NETWORK,
        pcap_path,
        description="Minimal PCAP fixture",
    )

    analysis_result = framework.execute_module("network", params={"pcap": str(pcap_path)})
    if analysis_result.status != "success":
        raise RuntimeError(
            "Network analysis failed:"
            f" {analysis_result.status} | {analysis_result.errors}"
        )

    report_module = ReportGenerator(case_dir=case.case_dir, config=framework.config)
    report_result = report_module.run(None, {"format": "html", "output_file": str(report_path)})
    if report_result.status != "success":
        raise RuntimeError(
            "Report generation failed:"
            f" {report_result.status} | {report_result.errors}"
        )

    if report_result.output_path is None or not Path(report_result.output_path).exists():
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_path = run_minimal_flow(args.workspace, args.report)
    print(f"Report generated at: {output_path}")


if __name__ == "__main__":
    main()
