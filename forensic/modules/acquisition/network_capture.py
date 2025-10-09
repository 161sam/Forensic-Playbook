"""Network capture module with live acquisition safeguards."""

from __future__ import annotations

import json
import shutil
import signal
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from ...core.chain_of_custody import ChainOfCustody
from ...core.evidence import Evidence
from ...core.module import AcquisitionModule, ModuleResult
from ...core.time_utils import utc_isoformat, utc_slug


class NetworkCaptureModule(AcquisitionModule):
    """Capture live network traffic into PCAP files."""

    def __init__(self, case_dir: Path, config: Dict):
        super().__init__(case_dir=case_dir, config=config)
        self.output_dir = self.case_dir / "acq" / "pcap"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._param_sources: Dict[str, str] = {}

    @property
    def name(self) -> str:
        return "network_capture"

    @property
    def description(self) -> str:
        return "Capture network packets with dumpcap/tcpdump"

    @property
    def requires_root(self) -> bool:
        return True

    @property
    def supported_evidence_types(self) -> list[str]:
        return ["network"]

    def _config_defaults(self) -> Dict[str, Any]:
        defaults = self._module_config("network")
        # Historical configuration files stored the values at the top-level
        # using ``default_*`` keys.  Preserve backwards compatibility by
        # translating them into the new structure.
        legacy_keys = {
            key: value for key, value in defaults.items() if key.startswith("default_")
        }
        if legacy_keys:
            defaults = {**defaults}
            for key, value in legacy_keys.items():
                normalized = key.replace("default_", "")
                defaults.setdefault(normalized, value)
        return defaults

    def validate_params(self, params: Dict) -> bool:
        defaults = self._config_defaults()

        original_params = dict(params)
        resolved: Dict[str, Any] = {}
        self._param_sources = {}

        def _resolve(
            key: str,
            *,
            builtin: Any = None,
            fallback_keys: Optional[Sequence[str]] = None,
        ) -> Any:
            if key in original_params:
                raw_value = original_params[key]
                if isinstance(raw_value, str):
                    trimmed = raw_value.strip()
                    if trimmed:
                        resolved[key] = trimmed
                        self._param_sources[key] = "cli"
                        return trimmed
                elif raw_value is not None:
                    resolved[key] = raw_value
                    self._param_sources[key] = "cli"
                    return raw_value

            search_keys: list[str] = [key]
            if fallback_keys:
                search_keys.extend(list(fallback_keys))
            search_keys.append(f"default_{key}")

            seen: set[str] = set()
            for candidate in search_keys:
                if candidate in seen:
                    continue
                seen.add(candidate)
                config_value = defaults.get(candidate)
                if isinstance(config_value, str):
                    config_value = config_value.strip()
                if config_value in (None, ""):
                    continue
                resolved[key] = config_value
                self._param_sources[key] = "config"
                return config_value

            if builtin is not None:
                resolved[key] = builtin
                self._param_sources[key] = "default"
                return builtin

            return None

        _resolve("duration", builtin=300)
        _resolve("interface", builtin="any")
        _resolve("bpf", builtin="not port 22")
        _resolve("count", builtin=None)
        _resolve("dry_run", builtin=False)
        _resolve("enable_live_capture", builtin=False)
        _resolve("tool", builtin="dumpcap", fallback_keys=["default_tool"])

        params.clear()
        params.update(resolved)

        for key, value in original_params.items():
            if key in params:
                continue
            params[key] = value
            self._param_sources.setdefault(key, "cli")

        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        del evidence  # Network capture operates on the local host only.

        result_id = self._generate_result_id()
        timestamp = utc_isoformat()
        parameter_sources = dict(getattr(self, "_param_sources", {}))

        def _to_bool(value: Any) -> bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in {"1", "true", "yes", "on"}:
                    return True
                if lowered in {"0", "false", "no", "off"}:
                    return False
            return bool(value)

        dry_run = _to_bool(params.get("dry_run", False))
        enable_live_capture = _to_bool(params.get("enable_live_capture", False))

        try:
            duration = int(params.get("duration", 300))
            if duration <= 0:
                raise ValueError
        except (TypeError, ValueError):
            metadata = {
                "duration": params.get("duration"),
                "parameter_sources": parameter_sources,
            }
            return self.guard_result(
                "Invalid duration specified. Duration must be a positive integer.",
                status="failed",
                metadata=metadata,
                result_id=result_id,
                timestamp=timestamp,
            )

        count_param = params.get("count")
        packet_count: Optional[int]
        if count_param in (None, ""):
            packet_count = None
        else:
            try:
                packet_count = int(count_param)
                if packet_count <= 0:
                    raise ValueError
            except (TypeError, ValueError):
                metadata = {
                    "count": count_param,
                    "parameter_sources": parameter_sources,
                }
                return self.guard_result(
                    "Invalid packet count specified. Count must be a positive integer.",
                    status="failed",
                    metadata=metadata,
                    result_id=result_id,
                    timestamp=timestamp,
                )

        interface = str(params.get("interface", "any"))
        bpf_filter = str(params.get("bpf", "not port 22"))
        hostname = params.get("hostname") or socket.gethostname() or "localhost"

        selection = self._select_capture_tool(
            params.get("tool"), parameter_sources.get("tool") == "cli"
        )
        if not selection:
            metadata = {
                "missing_tools": ["dumpcap", "tcpdump"],
                "interface": interface,
                "bpf": bpf_filter,
                "duration": duration,
                "count": packet_count,
                "parameter_sources": parameter_sources,
            }
            guidance = "Install dumpcap or tcpdump to enable network captures."
            return self.guard_result(
                "Neither dumpcap nor tcpdump is available. Capture skipped.",
                hints=[guidance],
                metadata=metadata,
                status="skipped",
                result_id=result_id,
                timestamp=timestamp,
            )

        tool_name, tool_path = selection
        slug = utc_slug()
        base_name = f"{hostname}_{slug}"
        output_path = self._ensure_unique_path(self.output_dir / f"{base_name}.pcap")
        meta_path = output_path.with_name(f"{output_path.stem}.meta.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        command = self._build_command(
            tool_name,
            tool_path,
            interface,
            bpf_filter,
            duration,
            packet_count,
            output_path,
        )

        metadata = {
            "timestamp": timestamp,
            "hostname": hostname,
            "interface": interface,
            "bpf": bpf_filter,
            "duration": duration,
            "count": packet_count,
            "tool": tool_name,
            "tool_path": tool_path,
            "command": command,
            "dry_run": dry_run,
            "parameter_sources": parameter_sources,
            "output": str(output_path),
            "enable_live_capture": enable_live_capture,
        }

        if dry_run:
            findings = [
                {
                    "type": "dry_run",
                    "description": "Dry-run enabled. Capture command prepared.",
                    "command": " ".join(command),
                    "output": str(output_path),
                    "parameter_sources": parameter_sources,
                }
            ]
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="success",
                timestamp=timestamp,
                output_path=None,
                findings=findings,
                metadata=metadata,
                errors=[],
            )

        if not enable_live_capture:
            message = (
                "Live capture is disabled. Re-run with --enable-live-capture to confirm "
                "intentional packet acquisition."
            )
            return self.guard_result(
                message,
                hints=["Pass --enable-live-capture to acknowledge live packet capture."],
                metadata=metadata,
                status="skipped",
                result_id=result_id,
                timestamp=timestamp,
            )

        try:
            stdout, stderr, returncode = self._execute_capture(
                command, tool_name, duration
            )
        except Exception as exc:  # pragma: no cover - subprocess failures handled here
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=[],
                metadata=metadata,
                errors=[f"Failed to execute {tool_name}: {exc}"],
            )

        metadata.update({"returncode": returncode, "stdout": stdout, "stderr": stderr})

        if returncode != 0 or not output_path.exists():
            error_message = f"{tool_name} did not complete successfully. Review stdout/stderr for details."
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=[],
                metadata=metadata,
                errors=[error_message],
            )

        metadata["size_bytes"] = output_path.stat().st_size
        metadata["sha256"] = self._compute_hash(output_path)
        hash_path = self._ensure_unique_path(
            output_path.with_suffix(f"{output_path.suffix}.sha256")
        )
        hash_path.write_text(
            f"{metadata['sha256']}  {output_path.name}\n", encoding="utf-8"
        )
        metadata["sha256_file"] = str(hash_path)

        meta_path = self._ensure_unique_meta(meta_path)
        meta_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8"
        )

        self._log_chain_of_custody(
            metadata["sha256"], output_path, meta_path, tool_name, hash_path
        )

        findings = [
            {
                "type": "network_capture",
                "description": f"Network traffic captured to {output_path.name}",
                "hash_sha256": metadata["sha256"],
                "size_bytes": metadata["size_bytes"],
                "duration": duration,
                "interface": interface,
            }
        ]

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status="success",
            timestamp=timestamp,
            output_path=output_path,
            findings=findings,
            metadata=metadata | {"metadata_file": str(meta_path)},
            errors=[],
        )

    def _select_capture_tool(
        self, requested: Optional[str], prefer_requested: bool
    ) -> Optional[tuple[str, str]]:
        candidates: list[str] = []
        if requested and prefer_requested:
            candidates.append(str(requested))

        for tool in ("dumpcap", "tcpdump"):
            if tool not in candidates:
                candidates.append(tool)

        if requested and not prefer_requested and requested not in candidates:
            candidates.append(str(requested))

        for tool in candidates:
            if not self._verify_tool(tool):
                continue
            tool_path = shutil.which(tool) or tool
            return tool, tool_path
        return None

    def _build_command(
        self,
        tool_name: str,
        tool_path: str,
        interface: str,
        bpf_filter: str,
        duration: int,
        packet_count: Optional[int],
        output_path: Path,
    ) -> list[str]:
        command = [tool_path]

        if tool_name == "dumpcap":
            command.extend(
                ["-i", interface, "-a", f"duration:{duration}", "-w", str(output_path)]
            )
            if packet_count is not None:
                command.extend(["-c", str(packet_count)])
            if bpf_filter:
                command.extend(["-f", bpf_filter])
        else:  # tcpdump
            command.extend(["-i", interface, "-w", str(output_path), "-nn", "-s", "0"])
            if packet_count is not None:
                command.extend(["-c", str(packet_count)])
            if bpf_filter:
                command.append(bpf_filter)

        return command

    def _execute_capture(
        self, command: Sequence[str], tool_name: str, duration: int
    ) -> tuple[str, str, int]:
        timeout = duration + 5 if tool_name == "dumpcap" else duration

        self.logger.debug("Executing capture command: %s", " ".join(command))

        process = (
            subprocess.Popen(  # noqa: S603 - command constructed from validated input
                list(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            sigint = getattr(signal, "SIGINT", 2)
            process.send_signal(sigint)
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=5)

        return stdout, stderr, process.returncode

    def _ensure_unique_path(self, path: Path) -> Path:
        candidate = path
        counter = 1
        while candidate.exists():
            candidate = candidate.with_name(f"{path.stem}_{counter}{path.suffix}")
            counter += 1
        return candidate

    def _ensure_unique_meta(self, path: Path) -> Path:
        candidate = path
        counter = 1
        while candidate.exists():
            candidate = candidate.with_name(f"{path.stem}_{counter}{path.suffix}")
            counter += 1
        return candidate

    def _log_chain_of_custody(
        self,
        hash_value: str,
        output_path: Path,
        meta_path: Path,
        tool_name: str,
        hash_file: Path,
    ) -> None:
        if not self.config.get("enable_coc", True):
            return

        workspace = self.case_dir.parent.parent
        coc_db = workspace / "chain_of_custody.db"

        try:
            coc = ChainOfCustody(coc_db)
            coc.log_event(
                event_type="EVIDENCE_COLLECTED",
                case_id=self.case_dir.name,
                actor=self.config.get("coc_actor", "Forensic-Playbook"),
                description=f"Network capture created: {output_path.name}",
                metadata={
                    "path": str(output_path),
                    "metadata_file": str(meta_path),
                    "hash_sha256": hash_value,
                    "hash_file": str(hash_file),
                    "tool": tool_name,
                },
                integrity_hash=hash_value,
            )
        except Exception:  # pragma: no cover - best effort logging
            self.logger.warning("Failed to log network capture to chain of custody.")


__all__ = ["NetworkCaptureModule"]
