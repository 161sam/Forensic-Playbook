"""Tests for router summary aggregation."""

from __future__ import annotations

import json
from pathlib import Path

from forensic.modules.router.summarize import RouterSummarizeModule

TIMESTAMP = "20240101T000000Z"


def _write_category(source: Path, category: str, entries: list[dict[str, object]]) -> None:
    payload = {
        "module": "router.extract",
        "category": category,
        "generated_at": TIMESTAMP,
        "schema": f"router/{category}/v1",
        "source_paths": [str(source / f"{category}.json")],
        "entries": entries,
    }
    (source / f"{TIMESTAMP}_{category}.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def test_router_summarize_dry_run_preview(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    source = case_dir / "router" / TIMESTAMP
    source.mkdir(parents=True)
    module = RouterSummarizeModule(case_dir, {"output_dir": "router"})

    params = {
        "case": str(case_dir),
        "source": str(source),
        "dry_run": True,
        "timestamp": TIMESTAMP,
    }

    result = module.run(None, case_dir, params)

    summary_path = source / f"{TIMESTAMP}_summary.md"
    assert result.status == "skipped"
    assert "Dry-run" in result.message
    assert not summary_path.exists()


def test_router_summarize_real_run_builds_markdown(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    source = case_dir / "router" / TIMESTAMP
    source.mkdir(parents=True)
    _write_category(source, "devices", [{"hostname": "gateway"}])
    _write_category(source, "eventlog", [{"preview": "WARN link down"}])
    module = RouterSummarizeModule(case_dir, {"output_dir": "router"})

    params = {
        "case": str(case_dir),
        "source": str(source),
        "dry_run": False,
        "timestamp": TIMESTAMP,
    }

    result = module.run(None, case_dir, params)

    summary_path = source / f"{TIMESTAMP}_summary.md"
    content = summary_path.read_text(encoding="utf-8")

    assert result.status == "success"
    assert summary_path.exists()
    assert "## Devices" in content
    assert "- Records: 1" in content
    assert f"[{TIMESTAMP}_devices.json]({TIMESTAMP}_devices.json)" in content
    assert "## DDNS" in content
    assert "Source: not available" in content
