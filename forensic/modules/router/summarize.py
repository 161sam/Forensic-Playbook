"""Summarize router analysis outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from forensic.core.time_utils import utc_isoformat

from .common import (
    RouterResult,
    format_plan,
    legacy_invocation,
    load_router_defaults,
    normalize_bool,
    resolve_parameters,
)


def _build_summary(input_dir: Path) -> dict:
    files = sorted(path for path in input_dir.rglob("*") if path.is_file())
    total_size = sum(path.stat().st_size for path in files)
    top_files = [
        {
            "path": str(path.relative_to(input_dir)),
            "size": path.stat().st_size,
        }
        for path in files[:10]
    ]
    return {
        "generated": utc_isoformat(),
        "overview": {
            "total_files": len(files),
            "total_size": total_size,
        },
        "findings": top_files,
    }


def summarize(params: Mapping[str, object]) -> RouterResult:
    """Create markdown or JSON summaries for router artifacts."""

    config = load_router_defaults("summarize")
    builtin = {
        "sections": ["overview", "findings"],
        "dry_run": False,
        "legacy": False,
    }

    resolved, _ = resolve_parameters(params, config, builtin)
    dry_run = normalize_bool(resolved.get("dry_run", False))
    legacy = normalize_bool(resolved.get("legacy", False))

    input_dir = resolved.get("in") or resolved.get("input")
    output_path = resolved.get("out") or resolved.get("output")

    if not input_dir:
        return RouterResult().guard("Missing --in directory for summarize command.", status="failed")
    if not output_path:
        return RouterResult().guard("Missing --out path for summarize command.", status="failed")

    input_dir = Path(input_dir)
    output_path = Path(output_path)

    if legacy:
        return legacy_invocation(
            "summarize_report.sh",
            [str(input_dir), str(output_path)],
            dry_run=dry_run,
        )

    if not input_dir.exists():
        return RouterResult().guard(
            f"Analysis directory {input_dir} does not exist.",
            status="failed",
        )

    summary = _build_summary(input_dir)
    sections = resolved.get("sections", ["overview", "findings"])

    result = RouterResult()
    result.data["input"] = str(input_dir)
    result.data["output"] = str(output_path)
    result.data["sections"] = sections

    if dry_run:
        plan = [
            f"Would summarise {summary['overview']['total_files']} file(s)",
            f"Would write summary to {output_path}",
        ]
        result.message = "Dry-run: summarize preview"
        result.details.extend(format_plan(plan))
        return result

    if output_path.suffix.lower() == ".json":
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump({key: summary[key] for key in sections if key in summary}, handle, indent=2, sort_keys=True)
    else:
        lines = ["# Router Forensic Summary", ""]
        if "overview" in sections and "overview" in summary:
            overview = summary["overview"]
            lines.append("## Overview")
            lines.append(f"Total files: {overview['total_files']}")
            lines.append(f"Total size: {overview['total_size']} bytes")
            lines.append("")
        if "findings" in sections and "findings" in summary:
            lines.append("## Findings")
            for finding in summary["findings"]:
                lines.append(f"- {finding['path']} ({finding['size']} bytes)")
            lines.append("")
        with output_path.open("w", encoding="utf-8") as handle:
            handle.write("\n".join(lines).strip() + "\n")

    result.message = "Summary generated"
    result.details.append(f"Wrote {output_path}")
    result.add_artifact(
        output_path,
        label="router_summary",
        dry_run=dry_run,
        hash_algorithm=config.get("hash_algorithm", "sha256"),
        coc_log=output_path.parent / "chain_of_custody.log",
    )
    return result


__all__ = ["summarize"]
