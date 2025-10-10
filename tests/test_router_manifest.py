from __future__ import annotations

import json
from pathlib import Path

from forensic.modules.router.manifest import RouterManifestModule


TIMESTAMP = "20240101T000000Z"


def _build_source_directory(base: Path) -> Path:
    source = base / "router" / TIMESTAMP
    source.mkdir(parents=True)
    (source / "alpha.json").write_text("{}", encoding="utf-8")
    (source / "beta.txt").write_text("sample", encoding="utf-8")
    return source


def test_router_manifest_dry_run_preview(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    source_dir = _build_source_directory(case_dir)
    module = RouterManifestModule(case_dir, {"output_dir": "router"})

    params = {
        "case": str(case_dir),
        "source": str(source_dir),
        "dry_run": True,
        "timestamp": TIMESTAMP,
    }

    result = module.run(None, case_dir, params)

    manifest_path = source_dir / f"{TIMESTAMP}_manifest.json"
    assert result.status == "skipped"
    assert "Dry-run" in result.message
    assert not manifest_path.exists()


def test_router_manifest_real_run_indexes_files(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    source_dir = _build_source_directory(case_dir)
    module = RouterManifestModule(case_dir, {"output_dir": "router"})

    params = {
        "case": str(case_dir),
        "source": str(source_dir),
        "dry_run": False,
        "timestamp": TIMESTAMP,
    }

    result = module.run(None, case_dir, params)

    manifest_path = source_dir / f"{TIMESTAMP}_manifest.json"
    assert manifest_path.exists()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    paths = [entry["path"] for entry in manifest["files"]]
    assert paths == sorted(paths)
    assert set(paths) == {"alpha.json", "beta.txt"}

    artifact = result.artifacts[0]
    assert "sha256" in artifact
    assert artifact["path"].endswith(f"{TIMESTAMP}_manifest.json")
