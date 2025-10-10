"""Wrapper around ``codex/start_all_forensic.sh`` with guard rails."""

from __future__ import annotations

import json
import os
import shlex
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import (
    CODEX_HOME_NAME,
    CONTROL_LOG_NAME,
    LOG_DIR_NAME,
    META_FILE_NAME,
    PID_FILE_NAME,
    CodexActionResult,
)
from .installer import (
    _build_command,
    _execute_plan,
    _hash_plan,
    _load_environment,
    _record_meta,
    _resolve_script,
    _resolve_workspace,
    _script_environment,
)


def _start_script() -> Path:
    return _resolve_script("start_all_forensic.sh")


def _command_details(command: Sequence[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def _read_pid(pid_file: Path) -> tuple[int | None, list[str]]:
    warnings: list[str] = []
    if not pid_file.exists():
        return None, warnings

    try:
        raw = pid_file.read_text(encoding="utf-8").strip()
    except OSError as exc:  # pragma: no cover - unlikely
        warnings.append(f"Could not read PID file {pid_file}: {exc}")
        return None, warnings

    if not raw:
        warnings.append(f"PID file {pid_file} was empty")
        return None, warnings

    try:
        return int(raw), warnings
    except ValueError:
        warnings.append(f"PID file {pid_file} did not contain an integer")
        return None, warnings


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - rare on CI
        return True
    else:
        return True


def _load_meta_entries(meta_file: Path) -> list[dict[str, Any]]:
    if not meta_file.exists():
        return []

    entries: list[dict[str, Any]] = []
    for line in meta_file.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries.append(entry)

    entries.sort(key=lambda item: item.get("timestamp", ""))
    return entries


def start(
    workspace: Path | None = None,
    *,
    dry_run: bool = True,
    accept_risk: bool = False,
    foreground: bool = False,
    env: Mapping[str, str] | None = None,
) -> CodexActionResult:
    """Preview or execute the guarded Codex starter script."""

    environment = _load_environment(env)
    workspace_path = _resolve_workspace(workspace, environment)
    log_dir = workspace_path / LOG_DIR_NAME
    codex_home = workspace_path / CODEX_HOME_NAME
    script_path = _start_script()
    meta_file = log_dir / META_FILE_NAME
    control_log = log_dir / CONTROL_LOG_NAME
    pid_file = log_dir / PID_FILE_NAME

    if not script_path.exists():
        message = f"Start script missing at {script_path}"
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
                "control_log": str(control_log),
                "pid_file": str(pid_file),
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
        "Planned command: " + _command_details(command),
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
            "control_log": str(control_log),
            "pid_file": str(pid_file),
        },
        "plan": plan,
        "plan_hash": plan_hash,
    }

    warnings = list(command_warnings)

    if dry_run:
        message = "Dry-run: Codex start actions prepared."
        return CodexActionResult(
            status="success",
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
        "command": "start",
        "timestamp": timestamp,
        "plan_hash": plan_hash,
        "workspace": str(workspace_path),
        "returncode": process.returncode,
    }
    _record_meta(meta_file, meta_entry)

    if process.returncode == 0:
        message = "Codex starter completed."
        status = "success"
        errors: list[str] = []
    else:
        message = f"Starter exited with code {process.returncode}."
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


def stop(
    workspace: Path | None = None,
    *,
    dry_run: bool = True,
    accept_risk: bool = False,
    foreground: bool = False,
    env: Mapping[str, str] | None = None,
) -> CodexActionResult:
    """Preview or stop a running Codex MCP server using the PID file."""

    del accept_risk, foreground  # explicitly unused but part of shared signature

    environment = _load_environment(env)
    workspace_path = _resolve_workspace(workspace, environment)
    log_dir = workspace_path / LOG_DIR_NAME
    pid_file = log_dir / PID_FILE_NAME
    meta_file = log_dir / META_FILE_NAME

    pid, pid_warnings = _read_pid(pid_file)
    plan = {
        "commands": ([["kill", str(pid)]] if pid is not None else []),
        "environment": {
            "USB": str(workspace_path),
            "WORKSPACE": str(workspace_path),
            "LOGDIR": str(log_dir),
        },
        "working_directory": str(log_dir),
        "foreground": False,
    }
    plan_hash = _hash_plan(plan)
    data = {
        "dry_run": dry_run,
        "paths": {
            "workspace": str(workspace_path),
            "log_dir": str(log_dir),
            "pid_file": str(pid_file),
            "meta_file": str(meta_file),
        },
        "plan": plan,
        "plan_hash": plan_hash,
        "pid": pid,
    }
    details = [f"PID file: {pid_file}"]
    warnings = list(pid_warnings)

    if pid is None:
        message = "No active MCP PID file found."
        return CodexActionResult(
            status="success",
            message=message,
            data=data,
            details=details,
            warnings=warnings,
        )

    details.append(f"Planned signal: SIGTERM to PID {pid}")

    if dry_run:
        message = f"Dry-run: would signal PID {pid}."
        return CodexActionResult(
            status="success",
            message=message,
            data=data,
            details=details,
            warnings=warnings,
        )

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        warnings.append(f"Process {pid} not running.")
    except PermissionError as exc:  # pragma: no cover - depends on CI perms
        warnings.append(f"Insufficient permissions to signal PID {pid}: {exc}")
    else:
        try:
            pid_file.unlink()
        except OSError:
            warnings.append(f"Could not remove PID file {pid_file}")

    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    meta_entry = {
        "command": "stop",
        "timestamp": timestamp,
        "plan_hash": plan_hash,
        "workspace": str(workspace_path),
        "pid": pid,
    }
    _record_meta(meta_file, meta_entry)

    message = f"Stop routine completed for PID {pid}."
    return CodexActionResult(
        status="success",
        message=message,
        data=data,
        details=details,
        warnings=warnings,
    )


def status(
    workspace: Path | None = None,
    *,
    dry_run: bool = True,
    accept_risk: bool = False,
    foreground: bool = False,
    env: Mapping[str, str] | None = None,
) -> CodexActionResult:
    """Report metadata about the Codex environment without side effects."""

    del accept_risk, foreground, dry_run  # parameters kept for signature parity

    environment = _load_environment(env)
    workspace_path = _resolve_workspace(workspace, environment)
    log_dir = workspace_path / LOG_DIR_NAME
    codex_home = workspace_path / CODEX_HOME_NAME
    meta_file = log_dir / META_FILE_NAME
    pid_file = log_dir / PID_FILE_NAME

    pid, pid_warnings = _read_pid(pid_file)
    running = pid is not None and _process_alive(pid)

    meta_entries = _load_meta_entries(meta_file)
    message = "Codex services active." if running else "Codex services not running."
    data = {
        "running": running,
        "pid": pid,
        "workspace": str(workspace_path),
        "log_dir": str(log_dir),
        "codex_home": str(codex_home),
        "pid_file": str(pid_file),
        "meta_file": str(meta_file),
        "known_operations": meta_entries,
    }
    details = [f"Log directory: {log_dir}", f"Meta file: {meta_file}"]

    return CodexActionResult(
        status="success",
        message=message,
        data=data,
        details=details,
        warnings=list(pid_warnings),
    )


__all__ = ["start", "stop", "status"]
