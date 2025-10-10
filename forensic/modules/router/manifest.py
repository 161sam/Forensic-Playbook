"""Evidence manifest generation helpers."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Mapping

from forensic.utils.hashing import compute_hash

from .common import (
    RouterResult,
    ensure_directory,
    format_plan,
    legacy_invocation,
    load_router_defaults,
    normalize_bool,
    resolve_parameters,
)


def write_manifest(params: Mapping[str, object]) -> RouterResult:
    """Create a manifest JSON/CSV file with deterministic ordering."""

    config = load_router_defaults("manifest")
    builtin = {
        "hash_algorithm": "sha256",
        "fields": ["path", "sha256", "size"],
        "source_dir": "router",
        "dry_run": False,
        "legacy": False,
        "log_name": "chain_of_custody.log",
    }

    resolved, _ = resolve_parameters(params, config, builtin)
    dry_run = normalize_bool(resolved.get("dry_run", False))
    legacy = normalize_bool(resolved.get("legacy", False))

    output_path = resolved.get("out") or resolved.get("output")
    if not output_path:
        return RouterResult().guard(
            "No output path provided for manifest generation.",
            status="failed",
        )

    output_path = Path(output_path)
    source_dir = Path(resolved.get("source") or resolved.get("source_dir") or output_path.parent)

    if legacy:
        return legacy_invocation(
            "generate_evidence_manifest.sh",
            [str(source_dir), str(output_path)],
            dry_run=dry_run,
        )

    if not source_dir.exists():
        return RouterResult().guard(
            f"Source directory {source_dir} not found.",
            hints=["Provide --source to override the default."],
        )

    files = sorted(path for path in source_dir.rglob("*") if path.is_file())
    records = []
    hash_algorithm = resolved.get("hash_algorithm", "sha256")
    log_name = resolved.get("log_name", "chain_of_custody.log")

    for path in files:
        if path.name == log_name:
            continue
        record = {
            "path": str(path.relative_to(source_dir)),
            "size": path.stat().st_size,
        }
        try:
            record[hash_algorithm] = compute_hash(path, algorithm=hash_algorithm)
        except Exception as exc:  # pragma: no cover - IO failures are rare
            record[hash_algorithm] = f"error: {exc}"
        records.append(record)

    result = RouterResult()
    result.data["records"] = records
    result.data["source_dir"] = str(source_dir)
    result.data["output"] = str(output_path)

    if dry_run:
        result.message = "Dry-run: manifest preview"
        result.details.extend(
            format_plan(
                [
                    f"Would write {len(records)} records to {output_path}",
                ]
            )
        )
        return result

    ensure_directory(output_path.parent)

    if output_path.suffix.lower() == ".csv":
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=resolved.get("fields", ["path", hash_algorithm, "size"]))
            writer.writeheader()
            for record in records:
                row = {key: record.get(key, "") for key in writer.fieldnames}
                writer.writerow(row)
    else:
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2, sort_keys=True)

    result.message = "Manifest written"
    result.details.append(f"Captured {len(records)} artifacts.")
    result.add_artifact(
        output_path,
        label="router_manifest",
        dry_run=dry_run,
        hash_algorithm=hash_algorithm,
        coc_log=source_dir / log_name,
    )
    return result


__all__ = ["write_manifest"]
