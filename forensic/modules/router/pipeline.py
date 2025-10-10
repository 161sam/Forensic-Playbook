"""Router forensic pipeline orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from forensic.core.config import load_yaml

from . import capture, env, extract, manifest, summarize
from .common import (
    RouterResult,
    format_plan,
    legacy_invocation,
    load_router_defaults,
    normalize_bool,
    resolve_parameters,
)


def _normalise_steps(steps: Iterable[Any]) -> list[dict[str, Any]]:
    normalised: list[dict[str, Any]] = []
    for step in steps or []:
        if isinstance(step, str):
            normalised.append({"handler": step, "params": {}})
            continue
        if isinstance(step, Mapping):
            if "handler" in step:
                normalised.append({"handler": str(step["handler"]), "params": dict(step.get("params", {}))})
                continue
            if len(step) == 1:
                key = next(iter(step))
                value = step[key]
                normalised.append({"handler": str(key), "params": dict(value or {})})
                continue
        normalised.append({"handler": str(step), "params": {}})
    return normalised


HANDLERS = {
    "env.init": lambda params: env.init_environment(params),
    "capture.setup": lambda params: capture.setup(params),
    "capture.start": lambda params: capture.start(params),
    "capture.stop": lambda params: capture.stop(params),
    "extract.ui": lambda params: extract.extract("ui", params),
    "extract.ddns": lambda params: extract.extract("ddns", params),
    "extract.devices": lambda params: extract.extract("devices", params),
    "extract.eventlog": lambda params: extract.extract("eventlog", params),
    "extract.portforwards": lambda params: extract.extract("portforwards", params),
    "extract.session_csrf": lambda params: extract.extract("session_csrf", params),
    "extract.tr069": lambda params: extract.extract("tr069", params),
    "extract.backups": lambda params: extract.extract("backups", params),
    "manifest.write": lambda params: manifest.write_manifest(params),
    "summarize": lambda params: summarize.summarize(params),
}


def run_pipeline(params: Mapping[str, Any]) -> RouterResult:
    """Execute the configured router forensic pipeline."""

    config = load_router_defaults("pipeline")
    builtin = {
        "steps": ["extract.ui", "summarize"],
        "fail_fast": True,
        "dry_run": False,
        "legacy": False,
    }

    resolved, _ = resolve_parameters(params, config, builtin)
    dry_run = normalize_bool(resolved.get("dry_run", False))
    legacy = normalize_bool(resolved.get("legacy", False))

    if legacy:
        return legacy_invocation(
            "run_forensic_pipeline.sh",
            [resolved.get("plan") or ""],
            dry_run=dry_run,
        )

    plan = resolved.get("plan")
    if plan:
        plan_path = Path(plan)
        if plan_path.exists():
            plan_data = load_yaml(plan_path)
            if isinstance(plan_data, Mapping):
                plan_steps = plan_data.get("steps")
                if plan_steps:
                    resolved["steps"] = plan_steps

    steps = _normalise_steps(resolved.get("steps", []))
    result = RouterResult()
    result.data["steps"] = steps

    if dry_run:
        preview = [f"Would run {step['handler']}" for step in steps]
        result.message = "Dry-run: router pipeline preview"
        result.details.extend(format_plan(preview))
        return result

    fail_fast = normalize_bool(resolved.get("fail_fast", True))
    step_results: list[dict[str, Any]] = []

    for step in steps:
        handler_name = step["handler"]
        handler = HANDLERS.get(handler_name)
        if not handler:
            step_results.append({"handler": handler_name, "status": "skipped", "reason": "unknown handler"})
            if fail_fast:
                result.status = "failed"
                result.message = f"Unknown pipeline handler {handler_name}"
                break
            continue

        outcome = handler(step.get("params", {}))
        step_results.append({
            "handler": handler_name,
            "status": outcome.status,
            "message": outcome.message,
        })
        result.details.append(f"{handler_name}: {outcome.status}")
        if outcome.status == "failed" and fail_fast:
            result.status = "failed"
            result.message = f"Pipeline halted after {handler_name} failure"
            break

    if result.status != "failed":
        result.message = "Router pipeline completed"

    result.data["step_results"] = step_results
    return result


__all__ = ["run_pipeline"]
