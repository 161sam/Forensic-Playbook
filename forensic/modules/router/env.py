"""Environment preparation helpers for router forensics."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from .common import (
    RouterResult,
    ensure_directory,
    format_plan,
    legacy_invocation,
    load_router_defaults,
    normalize_bool,
    resolve_parameters,
)


def init_environment(params: Mapping[str, object]) -> RouterResult:
    """Prepare the router forensic workspace."""

    config = load_router_defaults("env")
    builtin = {
        "directories": [
            "router/capture",
            "router/extract",
            "router/analysis",
            "router/reports",
        ],
        "coc_log": "router/chain_of_custody.log",
        "dry_run": False,
        "legacy": False,
    }

    resolved, _ = resolve_parameters(params, config, builtin)
    dry_run = normalize_bool(resolved.get("dry_run", False))
    legacy = normalize_bool(resolved.get("legacy", False))
    root_path = Path(resolved.get("root") or Path.cwd())

    if legacy:
        return legacy_invocation(
            "prepare_env.sh",
            [str(root_path)],
            dry_run=dry_run,
        )

    result = RouterResult()
    directories = [root_path / Path(directory) for directory in resolved["directories"]]

    if dry_run:
        result.message = "Dry-run: environment initialization preview"
        result.details.extend(
            format_plan(f"Would create directory {directory}" for directory in directories)
        )
        result.data["directories"] = [str(directory) for directory in directories]
        return result

    created: list[str] = []
    for directory in directories:
        ensure_directory(directory, dry_run=dry_run)
        created.append(str(directory))

    result.message = "Router workspace ready"
    result.details.append(f"Initialized {len(directories)} directories.")
    result.data["directories"] = created

    coc_log = root_path / resolved.get("coc_log", "router/chain_of_custody.log")
    ensure_directory(coc_log.parent, dry_run=dry_run)
    result.data["coc_log"] = str(coc_log)
    return result


__all__ = ["init_environment"]
