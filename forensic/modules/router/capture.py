"""Guarded tcpdump/dumpcap capture module."""

from __future__ import annotations

import json
import os
import shlex
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

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


class RouterCaptureModule(RouterModule):
    """Guarded module translating tcpdump scripts into deterministic actions."""

    module = "router.capture"
    description_text = "Guarded passive capture orchestration"

    def validate_params(self, params: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        self._validation_errors = []
        config = load_router_defaults("capture")
        builtin = {
            "interface": "any",
            "bpf": "not port 22",
            "duration": None,
            "count": None,
            "pcap_dir": "router/capture",
            "ring": False,
            "enable_live_capture": False,
            "dry_run": True,
            "action": "start",
            "timestamp": None,
        }

        resolved, _ = resolve_parameters(params, config, builtin)
        action = str(resolved.get("action", "start")).lower()
        if action not in {"setup", "start", "stop"}:
            self._validation_errors.append("action must be one of setup/start/stop")
            return None

        sanitized: Dict[str, Any] = {
            "action": action,
            "dry_run": normalize_bool(resolved.get("dry_run", True)),
            "interface": resolved.get("interface", "any"),
            "bpf": resolved.get("bpf", ""),
            "enable_live_capture": normalize_bool(resolved.get("enable_live_capture", False)),
            "ring": normalize_bool(resolved.get("ring", False)),
            "pcap_dir": Path(resolved.get("pcap_dir", "router/capture")),
        }

        timestamp = resolved.get("timestamp")
        if timestamp:
            sanitized["timestamp"] = str(timestamp)

        if action in {"start", "setup"}:
            try:
                duration_value = resolved.get("duration")
                sanitized["duration"] = int(duration_value) if duration_value is not None else None
            except (TypeError, ValueError):
                self._validation_errors.append("duration must be an integer")
                return None

            try:
                count_value = resolved.get("count")
                sanitized["count"] = int(count_value) if count_value is not None else None
            except (TypeError, ValueError):
                self._validation_errors.append("count must be an integer")
                return None

            duration = sanitized.get("duration")
            count = sanitized.get("count")
            if action == "start":
                if duration is None and count is None:
                    self._validation_errors.append("provide either duration or count for capture start")
                    return None
                if duration is not None and duration <= 0:
                    self._validation_errors.append("duration must be greater than zero")
                    return None
                if count is not None and count <= 0:
                    self._validation_errors.append("count must be greater than zero")
                    return None

        return sanitized

    def tool_versions(self) -> Dict[str, str]:
        return detect_tools("dumpcap", "tcpdump")

    def _prepare_directories(self, case_dir: Path, sanitized: Mapping[str, Any]) -> list[str]:
        directories = []
        target = sanitized.get("pcap_dir")
        if isinstance(target, Path) and not target.is_absolute():
            directories.append(str(case_dir / target))
        elif isinstance(target, Path):
            directories.append(str(target))
        elif isinstance(target, str):
            directories.append(str(case_dir / target))
        return directories

    def _run_setup(
        self,
        case_dir: Path,
        sanitized: Mapping[str, Any],
        result: RouterResult,
    ) -> RouterResult:
        directories = [Path(path) for path in self._prepare_directories(case_dir, sanitized)]
        dry_run = sanitized.get("dry_run", True)

        if dry_run:
            result.status = "skipped"
            result.message = "Dry-run: capture setup preview"
            result.details.extend(format_plan(f"Would create {directory}" for directory in directories))
            result.data["directories"] = [str(directory) for directory in directories]
            return result

        created: list[str] = []
        for directory in directories:
            ensure_directory(directory, dry_run=False)
            created.append(str(directory))
        result.status = "success"
        result.message = "Capture directories ready"
        result.data["directories"] = created
        result.add_output(*created)
        return result

    def _run_start(
        self,
        case_dir: Path,
        sanitized: Mapping[str, Any],
        ts: str,
        result: RouterResult,
    ) -> RouterResult:
        dry_run = sanitized.get("dry_run", True)
        router_dir = self._router_dir()
        timestamp = sanitized.get("timestamp", ts)
        run_dir = router_dir / str(timestamp)
        pcap_dir = Path(sanitized.get("pcap_dir", run_dir))
        if not pcap_dir.is_absolute():
            pcap_dir = case_dir / pcap_dir
        capture_dir = ensure_directory(pcap_dir if not dry_run else pcap_dir, dry_run=dry_run)
        output_dir = capture_dir if capture_dir.is_dir() else capture_dir.parent

        pcap_file = output_dir / "capture.pcap"
        meta_file = output_dir / f"{timestamp}_capture.meta.json"

        tool_versions = self.tool_versions()
        preferred_tool = None
        for candidate in ("dumpcap", "tcpdump"):
            if candidate in tool_versions:
                preferred_tool = candidate
                break
        preferred_tool = preferred_tool or next(iter(tool_versions), "tcpdump")

        duration = sanitized.get("duration")
        count = sanitized.get("count")
        interface = sanitized.get("interface", "any")
        bpf = sanitized.get("bpf")

        command: list[str] = [preferred_tool, "-i", str(interface), "-w", str(pcap_file)]
        if duration is not None:
            command.extend(["-G", str(duration)])
        if count is not None:
            command.extend(["-c", str(count)])
        if sanitized.get("ring"):
            command.append("--use-ring-buffer")
        if bpf:
            command.append(str(bpf))

        rendered = " ".join(shlex.quote(part) for part in command)
        result.add_input("interface", interface)
        result.add_input("bpf", bpf)
        result.add_input("duration", duration)
        result.add_input("count", count)
        result.data["command"] = command
        result.data["pcap_file"] = str(pcap_file)
        result.data["meta_file"] = str(meta_file)

        if dry_run:
            result.status = "skipped"
            result.message = "Dry-run: capture start preview"
            result.details.extend(format_plan([f"Would execute: {rendered}"]))
            return result

        if not sanitized.get("enable_live_capture", False):
            return result.guard(
                "Live capture disabled by default.",
                hints=["Re-run with enable_live_capture=True to permit capture."],
            )

        tool_path = tool_versions.get(preferred_tool)
        if not tool_path:
            return result.guard(
                f"Required capture tool '{preferred_tool}' is not available.",
                hints=["Install tcpdump or dumpcap before attempting live capture."],
            )

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return result.guard(
                "Root privileges are required for live capture.",
                hints=["Run via sudo or delegate capture to a privileged host."],
            )

        ensure_directory(output_dir, dry_run=False)
        payload = {
            "timestamp": timestamp,
            "tool": preferred_tool,
            "tool_path": tool_path,
            "command": command,
            "interface": interface,
            "duration": duration,
            "count": count,
            "bpf": bpf,
            "executed": False,
        }

        with meta_file.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)

        result.status = "success"
        result.message = "Capture command prepared"
        result.details.append(f"Command staged: {rendered}")
        result.add_artifact(meta_file, case_dir=case_dir, dry_run=False)
        if pcap_file.exists():
            result.add_artifact(pcap_file, case_dir=case_dir, dry_run=False)
        else:
            result.details.append("PCAP file reserved; no capture executed by default.")
        return result

    def _run_stop(self, result: RouterResult) -> RouterResult:
        guidance = [
            "Identify running tcpdump/dumpcap processes",
            "Send SIGINT (Ctrl+C) to stop capture",
            "Verify PCAP files are rotated and closed",
        ]
        result.status = "skipped"
        result.message = "Passive capture stop guidance"
        result.details.extend(format_plan(guidance))
        return result

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
        result.add_input("case_dir", str(case_dir))

        if sanitized is None:
            result.status = "failed"
            result.message = "; ".join(self._validation_errors) or "Invalid parameters"
            result.errors.extend(self._validation_errors)
            self._log_provenance(
                ts=ts,
                params=params,
                tool_versions=self.tool_versions(),
                result=result,
                inputs=result.inputs,
                duration_ms=(time.perf_counter() - start) * 1000,
                exit_code=1,
            )
            return result

        action = sanitized.get("action", "start")
        if action == "setup":
            self._run_setup(case_dir, sanitized, result)
        elif action == "start":
            self._run_start(case_dir, sanitized, ts, result)
        else:
            self._run_stop(result)

        duration_ms = (time.perf_counter() - start) * 1000
        exit_code = 0 if result.status not in {"failed"} else 1
        params_for_log = dict(sanitized)
        params_for_log["action"] = action
        self._log_provenance(
            ts=ts,
            params=params_for_log,
            tool_versions=self.tool_versions(),
            result=result,
            inputs=result.inputs,
            duration_ms=duration_ms,
            exit_code=exit_code,
        )
        return result


def setup(params: Mapping[str, Any]) -> RouterResult:
    """Prepare capture directories via the guarded module."""

    case_dir = Path(params.get("case") or params.get("root") or Path.cwd())
    scoped = dict(params)
    scoped["action"] = "setup"
    module = RouterCaptureModule(case_dir, load_router_defaults("capture"))
    return module.run(None, case_dir, scoped)


def start(params: Mapping[str, Any]) -> RouterResult:
    """Stage or preview a capture command."""

    case_dir = Path(params.get("case") or params.get("root") or Path.cwd())
    scoped = dict(params)
    scoped["action"] = "start"
    module = RouterCaptureModule(case_dir, load_router_defaults("capture"))
    return module.run(None, case_dir, scoped)


def stop(params: Mapping[str, Any]) -> RouterResult:
    """Provide guidance for stopping captures."""

    case_dir = Path(params.get("case") or params.get("root") or Path.cwd())
    scoped = dict(params)
    scoped["action"] = "stop"
    module = RouterCaptureModule(case_dir, load_router_defaults("capture"))
    return module.run(None, case_dir, scoped)


__all__ = ["RouterCaptureModule", "setup", "start", "stop"]
