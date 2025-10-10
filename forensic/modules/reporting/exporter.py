"""Reporting exporters and helpers for report generation outputs."""

from __future__ import annotations

import copy
import html
import importlib
import json
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

try:  # pragma: no cover - optional dependency
    from jinja2 import Environment, PackageLoader, select_autoescape
except ImportError as exc:  # pragma: no cover - optional dependency
    Environment = None  # type: ignore[assignment]
    PackageLoader = None  # type: ignore[assignment]
    select_autoescape = None  # type: ignore[assignment]
    _JINJA2_IMPORT_ERROR = exc
else:
    _JINJA2_IMPORT_ERROR = None

from ...core.time_utils import utc_display

_TEMPLATE_PACKAGE = "forensic.modules.reporting"


def _is_scalar(value: Any) -> bool:
    return isinstance(value, str | int | float | bool) or value is None


def _normalise_structure(value: Any) -> Any:
    """Recursively sort mappings and scalar lists for deterministic output."""

    if isinstance(value, dict):
        return {key: _normalise_structure(value[key]) for key in sorted(value)}

    if isinstance(value, list):
        normalised = [_normalise_structure(item) for item in value]
        if all(_is_scalar(item) for item in normalised):
            return sorted(normalised)
        return normalised

    if isinstance(value, tuple):
        return tuple(_normalise_structure(list(value)))

    return value


def _ensure_jinja2() -> None:
    """Ensure that the optional Jinja2 dependency is available."""

    if (
        _JINJA2_IMPORT_ERROR is not None
        or Environment is None
        or PackageLoader is None
        or select_autoescape is None
    ):
        raise RuntimeError(
            "HTML report rendering requires the 'jinja2' package to be installed"
        ) from _JINJA2_IMPORT_ERROR


@lru_cache(maxsize=1)
def _get_environment() -> Environment:
    """Return a cached Jinja environment for report templates."""

    _ensure_jinja2()

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
        payload = _normalise_structure(data)
        outpath.write_text(
            json.dumps(payload, indent=2, default=str, sort_keys=True),
            encoding="utf-8",
        )
    elif fmt in {"md", "markdown"}:
        outpath.write_text(_to_markdown(data), encoding="utf-8")
    elif fmt == "html":
        try:
            _ensure_jinja2()
        except RuntimeError:
            outpath.write_text(_fallback_html(data), encoding="utf-8")
        else:
            outpath.write_text(_to_html(data), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported export format: {fmt}")

    return outpath


@lru_cache(maxsize=1)
def get_pdf_renderer() -> str | None:
    """Return the available PDF renderer, if any."""

    if shutil.which("wkhtmltopdf"):
        return "wkhtmltopdf"

    try:
        importlib.import_module("weasyprint")
    except ImportError:
        return None

    return "weasyprint"


def export_pdf(html_path: Path, pdf_path: Path) -> Path:
    """Convert an HTML report at ``html_path`` to PDF at ``pdf_path``."""

    renderer = get_pdf_renderer()
    if renderer is None:
        raise RuntimeError("PDF generation requires wkhtmltopdf or weasyprint")

    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    if renderer == "wkhtmltopdf":
        subprocess.run(
            [
                "wkhtmltopdf",
                "--enable-local-file-access",
                str(html_path),
                str(pdf_path),
            ],
            check=True,
            timeout=300,
        )
    else:
        from weasyprint import HTML

        HTML(filename=str(html_path)).write_pdf(pdf_path)

    return pdf_path


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


def _fallback_html(data: Dict[str, Any]) -> str:
    """Render a minimal HTML report without optional dependencies."""

    case = data.get("case", {}) if isinstance(data, dict) else {}
    title = case.get("name") or case.get("case_id") or "Case Overview"
    subtitle = html.escape(str(title))

    return f"""<!DOCTYPE html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\">
    <title>Forensic Investigation Report</title>
    <style>
      body {{ font-family: Arial, sans-serif; margin: 2rem; }}
      h1 {{ color: #1f2933; }}
      .marker {{ color: #52606d; font-size: 0.95rem; }}
    </style>
  </head>
  <body>
    <h1>Forensic Investigation Report</h1>
    <h2>{subtitle}</h2>
    <p class=\"marker\" data-marker=\"report-fallback\">
      HTML rendering via fallback template.
    </p>
  </body>
</html>
"""


__all__ = ["export_report", "export_pdf", "get_pdf_renderer"]
