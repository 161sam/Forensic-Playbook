"""Router artifact extraction module."""

from __future__ import annotations

import csv
import io
import json
import tarfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .common import (
    RouterModule,
    RouterResult,
    detect_tools,
    ensure_directory,
    format_plan,
    load_router_defaults,
    normalize_bool,
    resolve_parameters,
)

CATEGORY_ORDER = [
    "devices",
    "ddns",
    "eventlog",
    "portforwards",
    "tr069",
    "ui_artifacts",
    "backups",
]


def _categorize(name: str) -> str:
    lowered = name.lower()
    if "device" in lowered:
        return "devices"
    if "ddns" in lowered:
        return "ddns"
    if "event" in lowered or "syslog" in lowered or "log" in lowered:
        return "eventlog"
    if "port" in lowered or "forward" in lowered:
        return "portforwards"
    if "tr069" in lowered or "acs" in lowered:
        return "tr069"
    if lowered.endswith((".tar", ".tar.gz", ".tgz")) or "backup" in lowered:
        return "backups"
    return "ui_artifacts"


def _safe_member(name: str) -> bool:
    path = Path(name)
    if name.startswith("/"):
        return False
    return ".." not in path.parts


def _summarize_text(handle: io.TextIOBase, limit: int = 500) -> str:
    content = handle.read(limit)
    if len(content) == limit:
        return content + "…"
    return content


class RouterExtractModule(RouterModule):
    """Extract router UI artifacts and configuration exports."""

    module = "router.extract"
    description_text = "Parse router exports into structured JSON"

    def validate_params(self, params: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        self._validation_errors = []
        config = load_router_defaults("extract")
        builtin = {
            "input": None,
            "include_patterns": ["*.log", "*.txt", "*.json", "*.conf", "*.tar", "*.tar.gz", "*.tgz"],
            "max_bytes": 10 * 1024 * 1024,
            "dry_run": True,
            "timestamp": None,
        }

        resolved, _ = resolve_parameters(params, config, builtin)
        input_path = resolved.get("input")
        if not input_path:
            self._validation_errors.append("input parameter is required")
            return None

        input_dir = Path(input_path)
        include_patterns = resolved.get("include_patterns")
        if isinstance(include_patterns, str):
            include_patterns = [pattern.strip() for pattern in include_patterns.split(",") if pattern.strip()]

        sanitized: Dict[str, Any] = {
            "input": input_dir,
            "include_patterns": list(include_patterns or builtin["include_patterns"]),
            "max_bytes": int(resolved.get("max_bytes", builtin["max_bytes"])),
            "dry_run": normalize_bool(resolved.get("dry_run", True)),
        }

        timestamp = resolved.get("timestamp")
        if timestamp:
            sanitized["timestamp"] = str(timestamp)

        return sanitized

    def tool_versions(self) -> Dict[str, str]:
        return detect_tools("tar", "gzip")

    def _gather_sources(self, input_dir: Path, patterns: Sequence[str]) -> List[Path]:
        files: List[Path] = []
        for pattern in patterns:
            files.extend(sorted(input_dir.rglob(pattern)))
        unique: List[Path] = []
        seen = set()
        for path in files:
            if path.is_file():
                key = path.resolve()
                if key not in seen:
                    seen.add(key)
                    unique.append(path)
        return unique

    def _parse_json(self, path: Path, limit: int) -> Any:
        if path.stat().st_size > limit:
            return {"error": "file too large", "size": path.stat().st_size}
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            try:
                return json.load(handle)
            except json.JSONDecodeError as exc:
                return {"error": f"invalid json: {exc}"}

    def _parse_csv(self, path: Path, limit: int) -> List[Dict[str, Any]]:
        if path.stat().st_size > limit:
            return [{"error": "file too large", "size": path.stat().st_size}]
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            reader = csv.DictReader(handle)
            return [dict(row) for row in reader]

    def _parse_text(self, path: Path, limit: int) -> str:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return _summarize_text(handle, limit=min(limit, 2000))

    def _handle_tar(self, path: Path, max_bytes: int) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {"path": str(path), "size": path.stat().st_size, "members": []}
        try:
            with tarfile.open(path, "r:*") as archive:
                for member in sorted(archive.getmembers(), key=lambda item: item.name):
                    if not member.isfile() or not _safe_member(member.name):
                        continue
                    metadata["members"].append({"name": member.name, "size": member.size})
        except tarfile.TarError as exc:
            metadata["error"] = f"tar error: {exc}"
        return metadata

    def _build_category_payload(
        self,
        category: str,
        timestamp: str,
        source_paths: Iterable[str],
        entries: Iterable[Any],
    ) -> Dict[str, Any]:
        payload = {
            "module": self.module,
            "category": category,
            "generated_at": timestamp,
            "schema": f"router/{category}/v1",
            "source_paths": sorted(set(source_paths)),
            "entries": [self._deterministic_entry(entry) for entry in entries],
        }
        return payload

    def _deterministic_entry(self, entry: Any) -> Any:
        if isinstance(entry, dict):
            return {key: self._deterministic_entry(entry[key]) for key in sorted(entry)}
        if isinstance(entry, list):
            return [self._deterministic_entry(item) for item in entry]
        return entry

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

        input_dir: Path = Path(sanitized["input"])
        patterns: Sequence[str] = sanitized["include_patterns"]
        max_bytes: int = int(sanitized.get("max_bytes", 10 * 1024 * 1024))
        dry_run: bool = sanitized.get("dry_run", True)

        result.add_input("input_dir", str(input_dir))
        result.data["include_patterns"] = list(patterns)

        timestamp = sanitized.get("timestamp", ts)
        router_dir = self._router_dir()
        output_dir = router_dir / str(timestamp)
        ensure_directory(output_dir, dry_run=dry_run)

        source_files = self._gather_sources(input_dir, patterns)
        result.data["source_count"] = len(source_files)

        planned_outputs = [output_dir / f"{timestamp}_{category}.json" for category in CATEGORY_ORDER]
        if dry_run:
            result.status = "skipped"
            result.message = "Dry-run: router extract preview"
            result.details.extend(
                format_plan(
                    [
                        f"Would process {len(source_files)} files from {input_dir}",
                        *[f"Would generate {path.name}" for path in planned_outputs],
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

        category_sources: Dict[str, List[str]] = {name: [] for name in CATEGORY_ORDER}
        category_entries: Dict[str, List[Any]] = {name: [] for name in CATEGORY_ORDER}

        for file_path in source_files:
            category = _categorize(file_path.name)
            category_sources.setdefault(category, []).append(str(file_path))
            suffix = file_path.suffix.lower()
            if suffix == ".json":
                category_entries.setdefault(category, []).append(self._parse_json(file_path, max_bytes))
            elif suffix in {".csv", ".tsv"}:
                category_entries.setdefault(category, []).extend(self._parse_csv(file_path, max_bytes))
            elif suffix in {".tar", ".gz", ".tgz", ".tar.gz"} or category == "backups":
                category_entries.setdefault(category, []).append(self._handle_tar(file_path, max_bytes))
            else:
                category_entries.setdefault(category, []).append(
                    {"path": str(file_path), "preview": self._parse_text(file_path, max_bytes)}
                )

        artifacts: List[Path] = []
        ensure_directory(output_dir, dry_run=False)

        for category in CATEGORY_ORDER:
            payload = self._build_category_payload(
                category,
                str(timestamp),
                category_sources.get(category, []),
                category_entries.get(category, []),
            )
            output_file = output_dir / f"{timestamp}_{category}.json"
            with output_file.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
            artifacts.append(output_file)
            result.add_artifact(output_file, case_dir=case_dir, dry_run=False)

        result.status = "success"
        result.message = (
            f"Extracted router artifacts to {output_dir}"
            if artifacts
            else "No matching router artifacts discovered"
        )
        result.data["outputs"] = [str(path) for path in artifacts]

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


def extract(kind: str, params: Mapping[str, Any]) -> RouterResult:
    """Backward-compatible wrapper for CLI usage."""

    case_dir = Path(params.get("case") or params.get("out") or Path.cwd())
    scoped = dict(params)
    scoped.setdefault("kind", kind)
    module = RouterExtractModule(case_dir, load_router_defaults("extract"))
    return module.run(None, case_dir, scoped)


__all__ = ["RouterExtractModule", "extract"]
