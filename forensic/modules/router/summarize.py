"""Router summary generation module."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .common import (
    RouterModule,
    RouterResult,
    ensure_directory,
    format_plan,
    load_router_defaults,
    normalize_bool,
    resolve_parameters,
)

SUMMARY_SECTIONS: List[Tuple[str, str]] = [
    ("Devices", "devices"),
    ("Port Forwards", "portforwards"),
    ("DDNS", "ddns"),
    ("TR-069", "tr069"),
    ("Backups", "backups"),
    ("Events", "eventlog"),
]


class RouterSummarizeModule(RouterModule):
    """Generate Markdown summaries for router artifacts."""

    module = "router.summarize"
    description_text = "Summarize router extraction outputs"

    def validate_params(self, params: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        self._validation_errors = []
        config = load_router_defaults("summary")
        builtin = {
            "source": None,
            "output": None,
            "dry_run": True,
            "timestamp": None,
        }

        resolved, _ = resolve_parameters(params, config, builtin)
        source = resolved.get("source")
        if not source:
            self._validation_errors.append("source directory is required")
            return None

        sanitized: Dict[str, Any] = {
            "source": Path(source),
            "dry_run": normalize_bool(resolved.get("dry_run", True)),
        }

        output = resolved.get("output")
        if output:
            sanitized["output"] = Path(output)

        timestamp = resolved.get("timestamp")
        if timestamp:
            sanitized["timestamp"] = str(timestamp)

        return sanitized

    def tool_versions(self) -> Dict[str, str]:
        return {}

    def _load_category(self, source: Path, category: str) -> Tuple[Optional[Dict[str, Any]], Optional[Path]]:
        pattern = f"*_{category}.json"
        for candidate in sorted(source.glob(pattern)):
            try:
                with candidate.open("r", encoding="utf-8") as handle:
                    return json.load(handle), candidate
            except json.JSONDecodeError:
                continue
        return None, None

    def run(
        self,
        framework: Any,
        case: Path | str,
        params: Mapping[str, Any],
    ) -> RouterResult:
        ts = self._timestamp(params)
        start = time.perf_counter()
        case_dir = Path(case)
        sanitized = self.validate_params(params)
        result = RouterResult()

        if sanitized is None:
            result.status = "failed"
            result.message = "; ".join(self._validation_errors) or "Invalid parameters"
            result.errors.extend(self._validation_errors)
            self._log_provenance(
                ts=ts,
                params=params,
                tool_versions=self.tool_versions(),
                result=result,
                inputs={},
                duration_ms=(time.perf_counter() - start) * 1000,
                exit_code=1,
            )
            return result

        source: Path = Path(sanitized["source"])
        dry_run: bool = sanitized.get("dry_run", True)
        timestamp = sanitized.get("timestamp", ts)
        output_path = sanitized.get("output")
        if not output_path:
            output_path = source / f"{timestamp}_summary.md"

        result.add_input("source", str(source))
        result.data["output"] = str(output_path)

        if dry_run:
            result.status = "skipped"
            result.message = "Dry-run: summary preview"
            result.details.extend(
                format_plan(
                    [
                        f"Would read JSON artifacts from {source}",
                        f"Would write Markdown summary to {output_path}",
                    ]
                )
            )
            self._log_provenance(
                ts=ts,
                params=sanitized,
                tool_versions=self.tool_versions(),
                result=result,
                inputs=result.inputs,
                duration_ms=(time.perf_counter() - start) * 1000,
                exit_code=0,
            )
            return result

        if not source.exists():
            result.status = "failed"
            result.message = f"Source directory {source} does not exist"
            self._log_provenance(
                ts=ts,
                params=sanitized,
                tool_versions=self.tool_versions(),
                result=result,
                inputs=result.inputs,
                duration_ms=(time.perf_counter() - start) * 1000,
                exit_code=1,
            )
            return result

        lines: List[str] = ["# Router Forensic Summary", "", f"Generated at: {timestamp}", ""]
        summary_dir = output_path.parent
        ensure_directory(summary_dir, dry_run=False)

        for title, category in SUMMARY_SECTIONS:
            data, artifact_path = self._load_category(source, category)
            lines.append(f"## {title}")
            if data and artifact_path:
                entries = data.get("entries")
                count = len(entries) if isinstance(entries, list) else 0
                relative = artifact_path.relative_to(summary_dir)
                lines.append(f"- Records: {count}")
                lines.append(f"- Source: [{artifact_path.name}]({relative.as_posix()})")
            else:
                lines.append("- Records: 0")
                lines.append("- Source: not available")
            lines.append("")

        content = "\n".join(lines).strip() + "\n"
        with output_path.open("w", encoding="utf-8") as handle:
            handle.write(content)

        result.status = "success"
        result.message = f"Summary written to {output_path}"
        result.add_artifact(output_path, case_dir=case_dir, dry_run=False)

        self._log_provenance(
            ts=ts,
            params=sanitized,
            tool_versions=self.tool_versions(),
            result=result,
            inputs=result.inputs,
            duration_ms=(time.perf_counter() - start) * 1000,
            exit_code=0,
        )
        return result


def summarize(params: Mapping[str, Any]) -> RouterResult:
    """Backward-compatible wrapper for CLI usage."""

    case_dir = Path(params.get("case") or params.get("source") or Path.cwd())
    module = RouterSummarizeModule(case_dir, load_router_defaults("summary"))
    return module.run(None, case_dir, params)


__all__ = ["RouterSummarizeModule", "summarize"]
