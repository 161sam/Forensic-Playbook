"""Router manifest generation module."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from .common import (
    RouterModule,
    RouterResult,
    ensure_directory,
    format_plan,
    load_router_defaults,
    normalize_bool,
    resolve_parameters,
)


class RouterManifestModule(RouterModule):
    """Produce deterministic manifests for router extraction outputs."""

    module = "router.manifest"
    description_text = "Generate manifest of router artifacts"

    def validate_params(self, params: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        self._validation_errors = []
        config = load_router_defaults("manifest")
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

        source_path = Path(source)
        sanitized: Dict[str, Any] = {
            "source": source_path,
            "dry_run": normalize_bool(resolved.get("dry_run", True)),
        }

        timestamp = resolved.get("timestamp")
        if timestamp:
            sanitized["timestamp"] = str(timestamp)

        output = resolved.get("output")
        if output:
            sanitized["output"] = Path(output)

        return sanitized

    def tool_versions(self) -> Dict[str, str]:
        return {}

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
            output_path = source / f"{timestamp}_manifest.json"

        result.add_input("source", str(source))
        result.add_input("timestamp", str(timestamp))
        result.data["output"] = str(output_path)

        if dry_run:
            result.status = "skipped"
            result.message = "Dry-run: manifest preview"
            result.details.extend(
                format_plan(
                    [
                        f"Would index files under {source}",
                        f"Would write manifest to {output_path}",
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

        entries: List[Dict[str, Any]] = []
        for file_path in sorted(source.rglob("*")):
            if not file_path.is_file():
                continue
            stat = file_path.stat()
            rel = file_path.relative_to(source)
            entries.append(
                {
                    "path": str(rel).replace("\\", "/"),
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                }
            )

        ensure_directory(output_path.parent, dry_run=False)
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "module": self.module,
                    "generated_at": str(timestamp),
                    "files": entries,
                },
                handle,
                indent=2,
                sort_keys=True,
            )

        result.status = "success"
        result.message = f"Manifest written to {output_path}"
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


def write_manifest(params: Mapping[str, Any]) -> RouterResult:
    """Backward-compatible wrapper for CLI usage."""

    case_dir = Path(params.get("case") or params.get("source") or Path.cwd())
    module = RouterManifestModule(case_dir, load_router_defaults("manifest"))
    return module.run(None, case_dir, params)


__all__ = ["RouterManifestModule", "write_manifest"]
