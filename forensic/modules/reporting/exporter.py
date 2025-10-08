"""Reporting exporters for JSON and Markdown."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def export_report(data: Dict[str, Any], fmt: str, outpath: Path) -> Path:
    """Export ``data`` to ``outpath`` using the requested format."""

    fmt = fmt.lower()
    outpath.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        outpath.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    elif fmt in {"md", "markdown"}:
        outpath.write_text(_to_markdown(data), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported export format: {fmt}")

    return outpath


def _to_markdown(data: Dict[str, Any], level: int = 1) -> str:
    """Convert mapping to a simple Markdown bullet representation."""

    lines = []
    header = "#" * level + " Report"
    lines.append(header)
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"\n{'#' * (level + 1)} {key}")
            lines.append(_to_markdown(value, level + 1))
        else:
            lines.append(f"- **{key}**: {value}")
    return "\n".join(lines)


__all__ = ["export_report"]
