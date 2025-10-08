"""Tests for the reporting exporter helpers."""

import json
from pathlib import Path

import pytest

from forensic.modules.reporting.exporter import export_report


@pytest.fixture
def sample_report() -> dict:
    return {
        "case": {"id": "demo", "investigator": "Analyst"},
        "findings": {"count": 2},
    }


def test_export_report_json_round_trip(tmp_path: Path, sample_report: dict) -> None:
    output = tmp_path / "report.json"
    path = export_report(sample_report, "json", output)

    assert path == output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload == sample_report


def test_export_report_markdown_round_trip(tmp_path: Path, sample_report: dict) -> None:
    output = tmp_path / "report.md"
    path = export_report(sample_report, "md", output)

    assert path == output
    content = output.read_text(encoding="utf-8")
    assert "# Report" in content
    for key in sample_report:
        assert key in content


def test_export_report_rejects_unknown_format(tmp_path: Path, sample_report: dict) -> None:
    with pytest.raises(ValueError):
        export_report(sample_report, "pdf", tmp_path / "report.pdf")
