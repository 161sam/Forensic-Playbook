"""Router forensic pipeline orchestration module."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from .capture import RouterCaptureModule
from .common import (
    RouterModule,
    RouterResult,
    format_plan,
    load_router_defaults,
    normalize_bool,
    resolve_parameters,
)
from .env import RouterEnvModule
from .extract import RouterExtractModule
from .manifest import RouterManifestModule
from .summarize import RouterSummarizeModule


class RouterPipelineModule(RouterModule):
    """Orchestrate router modules with dry-run safeguards."""

    module = "router.pipeline"
    description_text = "Run router workflow pipeline"

    def validate_params(self, params: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        self._validation_errors = []
        config = load_router_defaults("pipeline")
        builtin = {
            "case": None,
            "dry_run": True,
            "with_capture": False,
            "fail_fast": True,
            "timestamp": None,
        }

        resolved, _ = resolve_parameters(params, config, builtin)
        case_dir = resolved.get("case") or params.get("case")
        case_path = Path(case_dir) if case_dir else Path.cwd()

        sanitized: Dict[str, Any] = {
            "case": case_path,
            "dry_run": normalize_bool(resolved.get("dry_run", True)),
            "with_capture": normalize_bool(resolved.get("with_capture", False)),
            "fail_fast": normalize_bool(resolved.get("fail_fast", True)),
        }

        timestamp = resolved.get("timestamp")
        if timestamp:
            sanitized["timestamp"] = str(timestamp)

        custom_steps = params.get("steps")
        if custom_steps is not None:
            if not isinstance(custom_steps, list) or not all(
                isinstance(item, str) for item in custom_steps
            ):
                self._validation_errors.append("steps must be a list of handler names")
                return None
            sanitized["steps"] = list(custom_steps)

        for key in ("env", "capture", "extract", "manifest", "summarize"):
            value = params.get(key) or {}
            if value and not isinstance(value, Mapping):
                self._validation_errors.append(f"{key} parameters must be a mapping")
                return None
            sanitized[key] = dict(value)

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

        case_dir: Path = Path(sanitized["case"])
        dry_run: bool = sanitized.get("dry_run", True)
        timestamp = sanitized.get("timestamp", ts)
        fail_fast: bool = sanitized.get("fail_fast", True)

        default_steps: List[str] = ["env"]
        if sanitized.get("with_capture"):
            default_steps.append("capture")
        default_steps.extend(["extract", "manifest", "summarize"])
        steps: List[str] = sanitized.get("steps", default_steps)

        step_results: List[Dict[str, Any]] = []
        plan_lines = [f"Would run {step}" for step in steps]
        result.add_input("case", str(case_dir))
        result.data["steps"] = steps

        if dry_run:
            result.status = "skipped"
            result.message = "Dry-run: router pipeline preview"
            result.details.extend(format_plan(plan_lines))
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

        exit_code = 0
        for step in steps:
            handler = HANDLERS.get(step)
            if not handler:
                message = f"Unknown pipeline handler {step}"
                step_results.append(
                    {"handler": step, "status": "failed", "message": message}
                )
                result.details.append(message)
                exit_code = 1
                if fail_fast:
                    break
                continue

            module_params = dict(sanitized.get(step, {}))
            module_params.setdefault("dry_run", dry_run)
            module_params.setdefault("timestamp", timestamp)
            if step == "env":
                module_params.setdefault("root", str(case_dir))
            handler_result = handler(case_dir, module_params)
            step_results.append(
                {
                    "handler": step,
                    "status": handler_result.status,
                    "message": handler_result.message,
                }
            )
            result.details.append(f"{step}: {handler_result.status}")
            if handler_result.status == "failed":
                exit_code = 1
                if fail_fast:
                    break

        if exit_code == 0:
            result.status = "success"
            result.message = "Router pipeline completed"
        else:
            result.status = "failed"
            result.message = "Router pipeline encountered errors"

        result.data["step_results"] = step_results

        self._log_provenance(
            ts=ts,
            params=sanitized,
            tool_versions=self.tool_versions(),
            result=result,
            inputs=result.inputs,
            duration_ms=(time.perf_counter() - start) * 1000,
            exit_code=exit_code,
        )
        return result


def _env_handler(case_dir: Path, params: Mapping[str, Any]) -> RouterResult:
    module = RouterEnvModule(case_dir, load_router_defaults("env"))
    return module.run(None, case_dir, params)


def _capture_handler(case_dir: Path, params: Mapping[str, Any]) -> RouterResult:
    module = RouterCaptureModule(case_dir, load_router_defaults("capture"))
    return module.run(None, case_dir, params)


def _extract_handler(case_dir: Path, params: Mapping[str, Any]) -> RouterResult:
    module = RouterExtractModule(case_dir, load_router_defaults("extract"))
    return module.run(None, case_dir, params)


def _manifest_handler(case_dir: Path, params: Mapping[str, Any]) -> RouterResult:
    module = RouterManifestModule(case_dir, load_router_defaults("manifest"))
    return module.run(None, case_dir, params)


def _summarize_handler(case_dir: Path, params: Mapping[str, Any]) -> RouterResult:
    module = RouterSummarizeModule(case_dir, load_router_defaults("summary"))
    return module.run(None, case_dir, params)


HANDLERS: Dict[str, Any] = {
    "env": _env_handler,
    "capture": _capture_handler,
    "capture.setup": _capture_handler,
    "capture.start": _capture_handler,
    "extract": _extract_handler,
    "extract.ui": _extract_handler,
    "manifest": _manifest_handler,
    "manifest.write": _manifest_handler,
    "summarize": _summarize_handler,
}


def run_pipeline(params: Mapping[str, Any]) -> RouterResult:
    """Backward-compatible wrapper for CLI usage."""

    case_dir = Path(params.get("case") or Path.cwd())
    module = RouterPipelineModule(case_dir, load_router_defaults("pipeline"))
    return module.run(None, case_dir, params)


__all__ = ["RouterPipelineModule", "run_pipeline", "HANDLERS"]
