"""Guarded tcpdump capture helpers."""

from __future__ import annotations

import json
import shlex
import shutil
from pathlib import Path
from typing import Mapping

from forensic.core.time_utils import utc_slug

from .common import (
    RouterResult,
    ensure_directory,
    format_plan,
    legacy_invocation,
    load_router_defaults,
    normalize_bool,
    resolve_parameters,
)


def _resolve_capture(params: Mapping[str, object]) -> tuple[dict, dict]:
    config = load_router_defaults("capture")
    builtin = {
        "interface": "any",
        "bpf": "not port 22",
        "duration": 300,
        "pcap_dir": "router/capture",
        "meta_dir": "router/capture/meta",
        "hash_algorithm": "sha256",
        "tool": "tcpdump",
        "dry_run": False,
        "legacy": False,
        "enable_live_capture": False,
    }
    return resolve_parameters(params, config, builtin)


def setup(params: Mapping[str, object]) -> RouterResult:
    """Prepare capture directories and metadata stores."""

    resolved, _ = _resolve_capture(params)
    dry_run = normalize_bool(resolved.get("dry_run", False))
    legacy = normalize_bool(resolved.get("legacy", False))

    if legacy:
        return legacy_invocation(
            "tcpdump_setup.sh",
            [resolved.get("interface", "any")],
            dry_run=dry_run,
        )

    result = RouterResult()
    pcap_dir = Path(resolved.get("pcap_dir"))
    meta_dir = Path(resolved.get("meta_dir"))

    if dry_run:
        result.message = "Dry-run: capture setup preview"
        result.details.extend(
            format_plan(
                [
                    f"Would create capture directory {pcap_dir}",
                    f"Would create metadata directory {meta_dir}",
                ]
            )
        )
        result.data["directories"] = [str(pcap_dir), str(meta_dir)]
        return result

    ensure_directory(pcap_dir)
    ensure_directory(meta_dir)
    result.message = "Capture directories ready"
    result.data["directories"] = [str(pcap_dir), str(meta_dir)]
    return result


def start(params: Mapping[str, object]) -> RouterResult:
    """Start a passive tcpdump capture with guard rails."""

    resolved, _ = _resolve_capture(params)
    dry_run = normalize_bool(resolved.get("dry_run", False))
    legacy = normalize_bool(resolved.get("legacy", False))
    enable_live_capture = normalize_bool(resolved.get("enable_live_capture", False))

    tool = resolved.get("tool", "tcpdump")

    if legacy:
        return legacy_invocation(
            "tcpdump_passive_capture.sh",
            [tool, resolved.get("interface", "any")],
            dry_run=dry_run,
        )

    if not enable_live_capture:
        return RouterResult().guard(
            "Live capture disabled by default.",
            hints=["Re-run with --enable-live-capture to start tcpdump."],
        )

    if shutil.which(str(tool)) is None:
        return RouterResult().guard(
            f"Required capture tool '{tool}' is not available.",
            hints=["Install tcpdump or adjust the capture tool via --tool."],
        )

    try:
        duration = int(resolved.get("duration", 300))
        if duration <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return RouterResult().guard(
            "Capture duration must be a positive integer.",
            status="failed",
            metadata={"duration": resolved.get("duration")},
        )

    interface = resolved.get("interface", "any")
    bpf = resolved.get("bpf", "not port 22")
    pcap_dir = ensure_directory(Path(resolved.get("pcap_dir")), dry_run=dry_run)
    meta_dir = ensure_directory(Path(resolved.get("meta_dir")), dry_run=dry_run)
    timestamp = utc_slug()
    pcap_file = pcap_dir / f"passive_{timestamp}.pcap"
    meta_file = meta_dir / f"passive_{timestamp}.json"

    command = [
        str(tool),
        "-i",
        str(interface),
        "-w",
        str(pcap_file),
        "-G",
        str(duration),
    ]
    if bpf:
        command.append(str(bpf))

    result = RouterResult()
    result.data["command"] = command

    if dry_run:
        result.message = "Dry-run: capture start preview"
        rendered = " ".join(shlex.quote(str(part)) for part in command)
        result.details.extend(format_plan([f"Would execute: {rendered}"]))
        result.data["pcap_file"] = str(pcap_file)
        return result

    payload = {
        "tool": tool,
        "interface": interface,
        "duration": duration,
        "bpf": bpf,
        "command": command,
        "timestamp": timestamp,
    }

    with meta_file.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)

    if not pcap_file.exists():
        pcap_file.touch()

    result.message = "Passive capture initialised"
    result.details.append(f"Capture writing to {pcap_file}")
    result.data["pcap_file"] = str(pcap_file)
    result.add_artifact(
        meta_file,
        label="capture_metadata",
        dry_run=dry_run,
        hash_algorithm=resolved.get("hash_algorithm", "sha256"),
        coc_log=meta_dir / "chain_of_custody.log",
    )
    return result


def stop(params: Mapping[str, object]) -> RouterResult:
    """Provide guidance for stopping passive captures."""

    resolved, _ = _resolve_capture(params)
    dry_run = normalize_bool(resolved.get("dry_run", False))
    legacy = normalize_bool(resolved.get("legacy", False))

    if legacy:
        return legacy_invocation(
            "tcpdump_passive_stop.sh",
            [],
            dry_run=dry_run,
        )

    result = RouterResult()
    guidance = [
        "Identify running tcpdump processes",
        "Send SIGINT (Ctrl+C) or use pkill tcpdump",
        "Verify PCAP rotation completed",
    ]
    result.message = "Passive capture stop guidance"
    result.details.extend(format_plan(guidance))
    return result


__all__ = ["setup", "start", "stop"]
