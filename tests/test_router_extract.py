from __future__ import annotations

import csv
import io
import json
import tarfile
from pathlib import Path

from forensic.modules.router.extract import CATEGORY_ORDER, RouterExtractModule

TIMESTAMP = "20240101T000000Z"


def _write_tar_gz(path: Path, name: str, content: str) -> None:
    data = content.encode("utf-8")
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))


def _build_input_directory(base: Path) -> Path:
    input_dir = base / "router_input"
    input_dir.mkdir()

    (input_dir / "devices.json").write_text(json.dumps([
        {"hostname": "router", "mac": "00:11:22:33:44:55"},
        {"hostname": "switch", "mac": "10:20:30:40:50:60"},
    ]), encoding="utf-8")

    (input_dir / "router_ddns.json").write_text(json.dumps({"ddns": "enabled"}), encoding="utf-8")

    (input_dir / "events.log").write_text("INFO Boot complete\nWARN Port flapping", encoding="utf-8")

    csv_path = input_dir / "port_forwards.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["name", "port"])
        writer.writeheader()
        writer.writerow({"name": "ssh", "port": "22"})

    (input_dir / "tr069_status.json").write_text(json.dumps({"acs": "active"}), encoding="utf-8")

    (input_dir / "ui.txt").write_text("UI config snapshot", encoding="utf-8")

    _write_tar_gz(input_dir / "config_backup.tar.gz", "config.txt", "firmware=1.0")

    return input_dir


def test_router_extract_dry_run_does_not_materialise_outputs(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    input_dir = _build_input_directory(tmp_path)
    module = RouterExtractModule(case_dir, {"output_dir": "router"})

    params = {
        "case": str(case_dir),
        "input": str(input_dir),
        "dry_run": True,
        "timestamp": TIMESTAMP,
    }

    result = module.run(None, case_dir, params)

    router_dir = case_dir / "router" / TIMESTAMP
    assert result.status == "skipped"
    assert "Dry-run" in result.message
    assert not router_dir.exists()


def test_router_extract_real_run_creates_structured_json(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    input_dir = _build_input_directory(tmp_path)
    module = RouterExtractModule(case_dir, {"output_dir": "router"})

    params = {
        "case": str(case_dir),
        "input": str(input_dir),
        "dry_run": False,
        "timestamp": TIMESTAMP,
    }

    result = module.run(None, case_dir, params)

    output_dir = case_dir / "router" / TIMESTAMP
    expected_files = [output_dir / f"{TIMESTAMP}_{category}.json" for category in CATEGORY_ORDER]

    assert result.status == "success"
    assert all(path.exists() for path in expected_files)

    devices_payload = json.loads((output_dir / f"{TIMESTAMP}_devices.json").read_text(encoding="utf-8"))
    assert list(devices_payload.keys()) == [
        "category",
        "entries",
        "generated_at",
        "module",
        "schema",
        "source_paths",
    ]
    devices_entries = devices_payload["entries"]
    assert isinstance(devices_entries[0], list)
    assert devices_entries[0][0]["hostname"] == "router"
    assert devices_payload["source_paths"] == [str(input_dir / "devices.json")]

    eventlog_payload = json.loads((output_dir / f"{TIMESTAMP}_eventlog.json").read_text(encoding="utf-8"))
    preview = eventlog_payload["entries"][0]["preview"]
    assert preview.startswith("INFO Boot complete")

    backups_payload = json.loads((output_dir / f"{TIMESTAMP}_backups.json").read_text(encoding="utf-8"))
    assert backups_payload["entries"][0]["members"][0]["name"] == "config.txt"
