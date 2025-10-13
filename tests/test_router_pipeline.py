from __future__ import annotations

import csv
import json
from pathlib import Path

from forensic.modules.router.pipeline import RouterPipelineModule

TIMESTAMP = "20240101T000000Z"


def _build_input_directory(base: Path) -> Path:
    input_dir = base / "router_pipeline_input"
    input_dir.mkdir()
    (input_dir / "devices.json").write_text(
        json.dumps([{"hostname": "gateway"}]), encoding="utf-8"
    )
    (input_dir / "events.log").write_text("INFO start", encoding="utf-8")
    (input_dir / "router_ddns.json").write_text(
        json.dumps({"enabled": True}), encoding="utf-8"
    )
    csv_path = input_dir / "port_forwards.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["name", "port"])
        writer.writeheader()
        writer.writerow({"name": "https", "port": "443"})
    return input_dir


def test_router_pipeline_dry_run_preview(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    input_dir = _build_input_directory(tmp_path)
    module = RouterPipelineModule(case_dir, {"output_dir": "router"})

    params = {
        "case": str(case_dir),
        "dry_run": True,
        "with_capture": True,
        "timestamp": TIMESTAMP,
        "extract": {"input": str(input_dir)},
    }

    result = module.run(None, case_dir, params)

    assert result.status == "skipped"
    assert "capture" in "".join(result.details).lower()
    planned_dir = case_dir / "router" / TIMESTAMP
    assert not planned_dir.exists()


def test_router_pipeline_real_run_executes_steps(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    input_dir = _build_input_directory(tmp_path)
    module = RouterPipelineModule(case_dir, {"output_dir": "router"})

    extract_source = case_dir / "router" / TIMESTAMP

    params = {
        "case": str(case_dir),
        "dry_run": False,
        "with_capture": False,
        "timestamp": TIMESTAMP,
        "extract": {"input": str(input_dir)},
        "manifest": {"source": str(extract_source)},
        "summarize": {"source": str(extract_source)},
    }

    result = module.run(None, case_dir, params)

    assert result.status == "success"
    handlers = [step["handler"] for step in result.data["step_results"]]
    assert handlers == ["env", "extract", "manifest", "summarize"]
    assert all(step["status"] == "success" for step in result.data["step_results"])

    run_dir = case_dir / "router" / TIMESTAMP
    manifest_path = run_dir / f"{TIMESTAMP}_manifest.json"
    summary_path = run_dir / f"{TIMESTAMP}_summary.md"

    assert manifest_path.exists()
    assert summary_path.exists()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    listed = {entry["path"] for entry in manifest["files"]}
    assert f"{TIMESTAMP}_devices.json" in listed

    capture_dir = case_dir / "router" / "capture"
    assert capture_dir.exists()

    summary_content = summary_path.read_text(encoding="utf-8")
    assert "## Devices" in summary_content
    assert "## Port Forwards" in summary_content
