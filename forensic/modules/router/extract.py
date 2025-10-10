"""Router artifact extraction helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

from forensic.core.time_utils import utc_isoformat, utc_slug

from .common import (
    RouterResult,
    ensure_directory,
    format_plan,
    legacy_invocation,
    load_router_defaults,
    normalize_bool,
    resolve_parameters,
)

LEGACY_SCRIPTS = {
    "ui": "extract_ui_artifacts.sh",
    "ddns": "extract_ddns.sh",
    "devices": "extract_devices.sh",
    "eventlog": "extract_eventlog.sh",
    "portforwards": "extract_portforwards.sh",
    "session_csrf": "extract_session_csrf.sh",
    "tr069": "extract_tr069.sh",
    "backups": "find_backups.sh",
}


def _read_preview(path: Path, encodings: Iterable[str]) -> str:
    for encoding in encodings:
        try:
            return path.read_text(encoding=encoding, errors="ignore")[:200]
        except Exception:  # pragma: no cover - encoding issues are environment specific
            continue
    return ""


def extract(kind: str, params: Mapping[str, object]) -> RouterResult:
    """Extract router artifacts of ``kind`` from ``input`` into ``out``."""

    config = load_router_defaults("extract")
    builtin = {
        "output_dir": "router/extract",
        "encodings": ["utf-8", "latin-1"],
        "patterns": {},
        "dry_run": False,
        "legacy": False,
    }

    resolved, _ = resolve_parameters(params, config, builtin)
    dry_run = normalize_bool(resolved.get("dry_run", False))
    legacy = normalize_bool(resolved.get("legacy", False))

    input_path = resolved.get("input") or resolved.get("source")
    if not input_path:
        return RouterResult().guard(
            "Extraction requires --input pointing to the collected artifacts.",
            status="failed",
        )
    input_path = Path(input_path)

    if not input_path.exists():
        if dry_run:
            result = RouterResult()
            result.message = f"Dry-run: extract {kind} preview"
            result.details.extend(
                format_plan([f"Input path {input_path} does not exist yet"])
            )
            return result
        return RouterResult().guard(
            f"Input path {input_path} not found.",
            status="failed",
        )

    if legacy:
        script = LEGACY_SCRIPTS.get(kind)
        if not script:
            return RouterResult().guard(
                f"No legacy script registered for extractor '{kind}'.",
                hints=["Available: " + ", ".join(sorted(LEGACY_SCRIPTS))],
            )
        return legacy_invocation(
            script,
            [str(input_path), str(resolved.get("out") or resolved.get("output") or "")],
            dry_run=dry_run,
        )

    patterns = config.get("patterns", {}).get(kind, ["*"])
    encodings = resolved.get("encodings", ["utf-8"])
    base_output = Path(resolved.get("out") or resolved.get("output_dir"))
    output_dir = ensure_directory(base_output / kind / utc_slug(), dry_run=dry_run)
    output_file = output_dir / f"{kind}_artifacts.json"

    matches: set[Path] = set()
    for pattern in patterns:
        matches.update(input_path.rglob(pattern))

    filtered = sorted(path for path in matches if path.is_file())

    result = RouterResult()
    result.data["input"] = str(input_path)
    result.data["output"] = str(output_file)
    result.data["pattern_count"] = len(patterns)

    if dry_run:
        plan = [
            f"Would search {input_path} for {len(patterns)} pattern(s)",
            f"Would write {len(filtered)} records to {output_file}",
        ]
        result.message = f"Dry-run: extract {kind} preview"
        result.details.extend(format_plan(plan))
        return result

    records = []
    for path in filtered:
        record = {
            "path": str(path.relative_to(input_path)),
            "size": path.stat().st_size,
            "modified": datetime.fromtimestamp(
                path.stat().st_mtime, tz=timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            "preview": _read_preview(path, encodings),
        }
        records.append(record)

    with output_file.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "kind": kind,
                "generated": utc_isoformat(),
                "input": str(input_path),
                "artifacts": records,
            },
            handle,
            indent=2,
            sort_keys=True,
        )

    result.message = f"Extracted {len(records)} {kind} artifact(s)"
    result.details.append(f"Wrote {output_file}")
    result.data["artifacts"] = records
    result.add_artifact(
        output_file,
        label=f"router_{kind}_artifacts",
        dry_run=dry_run,
        hash_algorithm=config.get("hash_algorithm", "sha256"),
        coc_log=output_dir / "chain_of_custody.log",
    )
    return result


__all__ = ["extract"]
