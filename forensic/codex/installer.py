"""Wrapper around ``codex/install_forensic_codex.sh`` with guard rails."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import (
    CODEX_HOME_NAME,
    DEFAULT_WORKSPACE,
    INSTALL_LOG_NAME,
    LOG_DIR_NAME,
    META_FILE_NAME,
    CodexActionResult,
    _repository_root,
)


try:  # pragma: no cover - environment dependent
    from forensic.utils.cmd import run_cmd  # type: ignore[attr-defined]
except (ImportError, AttributeError):  # pragma: no cover - fallback path
    def run_cmd(  # type: ignore[misc]
        command: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = False,
        capture_output: bool = True,
        text: bool = True,
    ) -> subprocess.CompletedProcess:
        """Fallback command runner relying on :mod:`subprocess`."""

        return subprocess.run(
            [str(part) for part in command],
            cwd=cwd,
            env=dict(env or {}),
            check=check,
            capture_output=capture_output,
            text=text,
        )


def _load_environment(env: Mapping[str, str] | None) -> dict[str, str]:
    base = dict(os.environ)
    if env:
        base.update(env)
    return base


def _resolve_workspace(
    workspace: Path | None, environment: Mapping[str, str]
) -> Path:
    candidates: list[Path] = []
    if workspace:
        candidates.append(workspace.expanduser())

    for key in ("FORENSIC_WORKSPACE", "WORKSPACE", "USB"):
        value = environment.get(key)
        if value:
            candidates.append(Path(value).expanduser())

    for candidate in candidates:
        if str(candidate):
            return candidate

    return DEFAULT_WORKSPACE


def _resolve_script(name: str) -> Path:
    return _repository_root() / "codex" / name


def _build_command(script_path: Path) -> tuple[list[str], list[str]]:
    warnings: list[str] = []
    if os.access(script_path, os.X_OK):
        return [str(script_path)], warnings

    shell = shutil.which("bash") or "/bin/bash"
    shell_path = Path(shell)
    if not shell_path.exists():
        raise FileNotFoundError("bash shell not available for script execution")
    warnings.append(
        f"Script is not marked executable; would invoke via {shell_path}"  # noqa: E501
    )
    return [str(shell_path), str(script_path)], warnings


def _script_environment(
    workspace: Path, log_dir: Path, codex_home: Path, environment: Mapping[str, str]
) -> dict[str, str]:
    script_env = dict(environment)
    script_env.update(
        {
            "USB": str(workspace),
            "WORKSPACE": str(workspace),
            "LOGDIR": str(log_dir),
            "CODEx_HOME": str(codex_home),
        }
    )
    return script_env


def _hash_plan(plan: dict[str, Any]) -> str:
    serialised = json.dumps(plan, sort_keys=True)
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


def _record_meta(meta_path: Path, entry: dict[str, Any]) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    existing: set[tuple[str, str]] = set()
    if meta_path.exists():
        for line in meta_path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = (record.get("command", ""), record.get("plan_hash", ""))
            existing.add(key)
    key = (entry.get("command", ""), entry.get("plan_hash", ""))
    if key in existing:
        return
    with meta_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def _execute_plan(
    command: Sequence[str], *, cwd: Path, env: Mapping[str, str]
) -> subprocess.CompletedProcess:
    return run_cmd(list(command), cwd=str(cwd), env=dict(env))


def install(
    workspace: Path | None = None,
    *,
    dry_run: bool = True,
    accept_risk: bool = False,
    foreground: bool = False,
    env: Mapping[str, str] | None = None,
) -> CodexActionResult:
    """Preview or execute the guarded Codex installer script."""

    environment = _load_environment(env)
    workspace_path = _resolve_workspace(workspace, environment)
    log_dir = workspace_path / LOG_DIR_NAME
    codex_home = workspace_path / CODEX_HOME_NAME
    script_path = _resolve_script("install_forensic_codex.sh")
    meta_file = log_dir / META_FILE_NAME
    log_file = log_dir / INSTALL_LOG_NAME

    if not script_path.exists():
        message = f"Installer script missing at {script_path}"
        data = {
            "dry_run": dry_run,
            "accept_risk": accept_risk,
            "paths": {
                "workspace": str(workspace_path),
                "log_dir": str(log_dir),
                "codex_home": str(codex_home),
                "script": str(script_path),
                "meta_file": str(meta_file),
                "log_file": str(log_file),
            },
        }
        return CodexActionResult(
            status="error",
            message=message,
            data=data,
            errors=[message],
        )

    command, command_warnings = _build_command(script_path)
    plan = {
        "commands": [command],
        "environment": {
            "USB": str(workspace_path),
            "WORKSPACE": str(workspace_path),
            "LOGDIR": str(log_dir),
            "CODEx_HOME": str(codex_home),
        },
        "working_directory": str(script_path.parent),
        "foreground": foreground,
    }
    plan_hash = _hash_plan(plan)
    details = [
        f"Script: {script_path}",
        f"Workspace: {workspace_path}",
        f"Log directory: {log_dir}",
        f"Codex HOME: {codex_home}",
        "Planned command: " + " ".join(shlex.quote(part) for part in command),
    ]
    data = {
        "dry_run": dry_run,
        "accept_risk": accept_risk,
        "foreground": foreground,
        "paths": {
            "workspace": str(workspace_path),
            "log_dir": str(log_dir),
            "codex_home": str(codex_home),
            "script": str(script_path),
            "meta_file": str(meta_file),
            "log_file": str(log_file),
        },
        "plan": plan,
        "plan_hash": plan_hash,
    }

    warnings = list(command_warnings)

    if dry_run:
        message = "Dry-run: Codex installer actions prepared."
        return CodexActionResult(
            status="success",
            message=message,
            data=data,
            details=details,
            warnings=warnings,
        )

    if not accept_risk:
        message = "Execution blocked: acknowledge risk with --accept-risk."
        warnings.append("Installer requires explicit risk acknowledgement (--accept-risk).")
        return CodexActionResult(
            status="warning",
            message=message,
            data=data,
            details=details,
            warnings=warnings,
        )

    script_env = _script_environment(workspace_path, log_dir, codex_home, environment)
    process = _execute_plan(command, cwd=script_path.parent, env=script_env)
    data.update(
        {
            "returncode": process.returncode,
            "stdout": process.stdout or "",
            "stderr": process.stderr or "",
        }
    )
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    meta_entry = {
        "command": "install",
        "timestamp": timestamp,
        "plan_hash": plan_hash,
        "workspace": str(workspace_path),
        "returncode": process.returncode,
    }
    _record_meta(meta_file, meta_entry)

    if process.returncode == 0:
        message = "Codex installer completed successfully."
        status = "success"
        errors: list[str] = []
    else:
        message = f"Installer exited with code {process.returncode}."
        status = "error"
        errors = [message]

    return CodexActionResult(
        status=status,
        message=message,
        data=data,
        details=details + [f"Return code: {process.returncode}"],
        warnings=warnings,
        errors=errors,
    )


__all__ = ["install"]
