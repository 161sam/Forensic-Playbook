"""Reporting exporters for JSON, Markdown and HTML."""

from __future__ import annotations

import copy
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, PackageLoader, select_autoescape

from ...core.time_utils import utc_display


_TEMPLATE_PACKAGE = "forensic.modules.reporting"


@lru_cache(maxsize=1)
def _get_environment() -> Environment:
    """Return a cached Jinja environment for report templates."""

    return Environment(
        loader=PackageLoader(_TEMPLATE_PACKAGE, "templates"),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _to_html(data: Dict[str, Any]) -> str:
    """Render the HTML report template using ``data``."""

    env = _get_environment()
    template = env.get_template("report.html")

    context = copy.deepcopy(data)
    statistics = context.setdefault("statistics", {})
    statistics.setdefault("report_time", utc_display())

    # Provide sensible defaults expected by the template
    context.setdefault("case", {})
    context.setdefault("executive_summary", None)
    context.setdefault("evidence", [])
    context.setdefault("findings", [])
    context.setdefault("timeline", {})
    context.setdefault("network", {})
    context.setdefault("chain_of_custody", [])

    return template.render(**context)


def export_report(data: Dict[str, Any], fmt: str, outpath: Path) -> Path:
    """Export ``data`` to ``outpath`` using the requested format."""

    fmt = fmt.lower()
    outpath.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        outpath.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    elif fmt in {"md", "markdown"}:
        outpath.write_text(_to_markdown(data), encoding="utf-8")
    elif fmt == "html":
        outpath.write_text(_to_html(data), encoding="utf-8")
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
