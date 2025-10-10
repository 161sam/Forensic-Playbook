"""Tests for the router environment preparation module."""

from __future__ import annotations

from pathlib import Path

from forensic.modules.router.env import RouterEnvModule

TIMESTAMP = "20240101T000000Z"


def test_router_env_dry_run_preview(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    module = RouterEnvModule(case_dir, {"output_dir": "router"})

    params = {
        "case": str(case_dir),
        "directories": ["router/custom", "router/reports"],
        "dry_run": True,
        "timestamp": TIMESTAMP,
    }

    result = module.run(None, case_dir, params)

    assert result.status == "skipped"
    assert "Dry-run" in result.message
    planned = {Path(detail.split(" ")[-1]) for detail in result.details}
    assert case_dir / "router" / "custom" in {case_dir / path for path in planned}
    assert not (case_dir / "router" / "custom").exists()
    assert not (case_dir / "router" / "reports").exists()


def test_router_env_real_run_creates_directories(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    module = RouterEnvModule(case_dir, {"output_dir": "router"})

    params = {
        "case": str(case_dir),
        "directories": ["router/capture", Path("router/extract")],
        "dry_run": False,
        "timestamp": TIMESTAMP,
    }

    result = module.run(None, case_dir, params)

    capture_dir = case_dir / "router" / "capture"
    extract_dir = case_dir / "router" / "extract"
    assert capture_dir.exists()
    assert extract_dir.exists()
    assert result.status == "success"
    assert sorted(result.outputs) == sorted([str(capture_dir), str(extract_dir)])
