"""Environment preparation module for router workflows."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .common import (
    RouterModule,
    RouterResult,
    ensure_directory,
    load_router_defaults,
    normalize_bool,
    resolve_parameters,
)


class RouterEnvModule(RouterModule):
    """Prepare the router workspace structure under a case directory."""

    module = "router.env"
    description_text = "Prepare router workspace directories"

    def validate_params(self, params: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        self._validation_errors = []
        config = load_router_defaults("env")
        builtin = {
            "directories": [
                "router/capture",
                "router/extract",
                "router/analysis",
                "router/reports",
            ],
            "dry_run": True,
            "coc_log": "meta/chain_of_custody.jsonl",
        }

        resolved, _ = resolve_parameters(params, config, builtin)

        directories = resolved.get("directories", [])
        if isinstance(directories, (str, Path)):
            directories = [directories]
        if not isinstance(directories, list) or not directories:
            self._validation_errors.append("directories must be a non-empty list of paths")
            return None

        sanitized: Dict[str, Any] = {
            "directories": [Path(directory) for directory in directories],
            "dry_run": normalize_bool(resolved.get("dry_run", True)),
            "coc_log": Path(resolved.get("coc_log", "meta/chain_of_custody.jsonl")),
        }

        root = resolved.get("root")
        if root:
            sanitized["root"] = Path(root)

        return sanitized

    def run(
        self,
        framework: Any,
        case: Path | str,
        params: Mapping[str, Any],
    ) -> RouterResult:
        ts = self._timestamp(params)
        start = time.perf_counter()  # type: ignore[name-defined]
        case_dir = Path(case)
        sanitized = self.validate_params(params)
        result = RouterResult()

        if sanitized is None:
            result.status = "failed"
            result.message = "; ".join(self._validation_errors) or "Invalid parameters"
            result.errors.extend(self._validation_errors)
            result.data["validated"] = False
            self._log_provenance(
                ts=ts,
                params=params,
                tool_versions=self.tool_versions(),
                result=result,
                inputs={},
                duration_ms=(time.perf_counter() - start) * 1000,  # type: ignore[name-defined]
                exit_code=1,
            )
            return result

        dry_run = sanitized["dry_run"]
        directories = []
        for directory in sanitized["directories"]:
            resolved_dir = directory
            if not resolved_dir.is_absolute():
                resolved_dir = case_dir / resolved_dir
            directories.append(resolved_dir)

        plan = [f"Would create {directory}" for directory in directories]
        result.add_input("case_dir", str(case_dir))
        result.data["directories"] = [str(directory) for directory in directories]

        if dry_run:
            result.status = "skipped"
            result.message = "Dry-run: environment initialization preview"
            result.details.extend(plan)
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

        created: list[str] = []
        for directory in directories:
            ensure_directory(directory, dry_run=dry_run)
            created.append(str(directory))

        result.status = "success"
        result.message = "Router workspace ready"
        result.details.append(f"Initialized {len(created)} directories")
        result.data["directories"] = created
        result.add_output(*created)

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


def init_environment(params: Mapping[str, Any]) -> RouterResult:
    """CLI-compatible wrapper for environment initialization."""

    case_dir = Path(params.get("case") or params.get("root") or Path.cwd())
    module = RouterEnvModule(case_dir, load_router_defaults("env"))
    return module.run(None, case_dir, params)


__all__ = ["RouterEnvModule", "init_environment"]
