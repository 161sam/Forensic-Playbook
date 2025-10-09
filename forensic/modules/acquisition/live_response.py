"""Live response collection module hardened for guarded operation."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...core.chain_of_custody import ChainOfCustody
from ...core.evidence import Evidence
from ...core.module import AcquisitionModule, ModuleResult
from ...utils import io

ALLOWED_COMMANDS: Dict[str, List[str]] = {
    "uname -a": ["uname", "-a"],
    "ps -ef": ["ps", "-ef"],
    "netstat -tulpen": ["netstat", "-tulpen"],
    "mount": ["mount"],
    "systemctl list-units": ["systemctl", "list-units"],
}


class LiveResponseModule(AcquisitionModule):
    """Collect read-only live response data from an allow-listed set of commands."""

    @property
    def name(self) -> str:
        return "live_response"

    @property
    def description(self) -> str:
        return "Collect host metadata using guarded read-only commands"

    @property
    def requires_root(self) -> bool:
        return False

    def validate_params(self, params: Dict) -> bool:
        resolved = self.resolve_param(
            "commands",
            params=params,
            default=list(ALLOWED_COMMANDS.keys()),
        )
        commands = self._normalise_commands(resolved)
        if not commands:
            self.logger.error("No commands specified for live response collection.")
            return False

        invalid = [cmd for cmd in commands if cmd not in ALLOWED_COMMANDS]
        if invalid:
            self.logger.error(
                "Unsupported command(s) requested: %s",
                ", ".join(sorted(invalid)),
            )
            return False

        params["commands"] = commands
        params["dry_run"] = self._as_bool(params.get("dry_run", False))
        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        del evidence  # Live response always operates on the local system.

        result_id = self._generate_result_id()
        timestamp = self.current_timestamp()

        raw_commands = params.get("commands")
        if not raw_commands:
            raw_commands = self.resolve_param(
                "commands",
                params=params,
                default=list(ALLOWED_COMMANDS.keys()),
            )

        commands = list(dict.fromkeys(self._normalise_commands(raw_commands)))
        dry_run = self._as_bool(params.get("dry_run", False))

        if not commands:
            message = "No live response commands selected after validation."
            return self.guard_result(
                message,
                hints=[
                    "Specify at least one allow-listed command via --param commands"
                ],
                status="skipped",
                metadata={"commands": []},
                result_id=result_id,
                timestamp=timestamp,
            )

        missing_tools = self._missing_tools(commands)
        planned_dir = self._planned_directory(timestamp)
        planned_steps = self._planned_steps(commands, planned_dir)

        if dry_run:
            metadata = self.dry_run_notice(planned_steps)
            metadata["commands"] = commands
            metadata["planned_directory"] = str(planned_dir)
            if missing_tools:
                metadata["missing_tools"] = missing_tools
                guard = self.guard_result(
                    "Required tooling missing for one or more commands.",
                    hints=[
                        "Install the missing tools or adjust the configured commands.",
                        f"Missing: {', '.join(missing_tools)}",
                    ],
                    status="partial",
                    metadata=metadata,
                    result_id=result_id,
                    timestamp=timestamp,
                )
                guard.errors.append(
                    "Dry-run detected missing tooling. No commands were executed."
                )
                return guard

            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="success",
                timestamp=timestamp,
                findings=[
                    {
                        "type": "dry_run",
                        "description": "Dry-run only logged planned live response commands.",
                        "commands": commands,
                    }
                ],
                metadata=metadata,
                errors=[],
            )

        if missing_tools:
            guard = self.guard_result(
                "Required tooling missing for one or more live response commands.",
                hints=[
                    "Install the missing tools or remove the associated commands.",
                    f"Missing: {', '.join(missing_tools)}",
                ],
                status="partial",
                metadata={"commands": commands, "missing_tools": missing_tools},
                result_id=result_id,
                timestamp=timestamp,
            )
            guard.errors.append("Live response aborted due to missing tooling.")
            return guard

        run_dir = planned_dir
        run_dir.mkdir(parents=True, exist_ok=True)

        command_records: List[Dict[str, Any]] = []
        artifacts: List[str] = []
        errors: List[str] = []

        for command in commands:
            execution = self._resolve_execution(command)
            if execution is None:
                errors.append(f"Skipping {command}: no available tooling.")
                continue

            argv, executed_display = execution
            safe_name = self._safe_filename(command)
            stdout_path = run_dir / f"{safe_name}.out"
            stderr_path = run_dir / f"{safe_name}.err"

            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
            )

            stdout_path.write_text(completed.stdout, encoding="utf-8")
            stderr_path.write_text(completed.stderr, encoding="utf-8")

            stdout_sha = self._compute_hash(stdout_path)
            stderr_sha = self._compute_hash(stderr_path)

            command_records.append(
                {
                    "requested": command,
                    "executed": executed_display,
                    "returncode": completed.returncode,
                    "stdout_path": str(stdout_path),
                    "stderr_path": str(stderr_path),
                    "stdout_sha256": stdout_sha,
                    "stderr_sha256": stderr_sha,
                }
            )

            artifacts.extend([str(stdout_path), str(stderr_path)])

            if completed.returncode != 0:
                errors.append(
                    f"Command '{executed_display}' exited with code {completed.returncode}."
                )

        meta_path = run_dir / "live_response.meta.json"
        hashes: List[Dict[str, str]] = []
        for record in command_records:
            hashes.append(
                {
                    "path": record["stdout_path"],
                    "sha256": record["stdout_sha256"],
                }
            )
            hashes.append(
                {
                    "path": record["stderr_path"],
                    "sha256": record["stderr_sha256"],
                }
            )

        unique_artifacts = sorted(dict.fromkeys(artifacts + [str(meta_path)]))
        metadata: Dict[str, Any] = {
            "commands": command_records,
            "artifacts": unique_artifacts,
            "run_directory": str(run_dir),
        }

        io.write_json(
            meta_path,
            {
                "module": self.name,
                "timestamp": timestamp,
                "commands": command_records,
                "hashes": hashes,
            },
        )

        meta_sha = self._compute_hash(meta_path)
        hashes.append({"path": str(meta_path), "sha256": meta_sha})
        hashes.sort(key=lambda entry: entry["path"])
        metadata["hashes"] = hashes

        self._log_chain_of_custody(meta_path, meta_sha, command_records, hashes)

        status = "success" if not errors else "partial"

        findings = [
            {
                "type": "live_response",
                "description": "Live response command execution completed.",
                "commands": commands,
            }
        ]

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=meta_path,
            findings=findings,
            metadata=metadata,
            errors=errors,
        )

    def _normalise_commands(self, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            entries = [item.strip() for item in value.split(",")]
            return [item for item in entries if item]
        if isinstance(value, list | tuple | set):
            normalised: List[str] = []
            for item in value:
                if item is None:
                    continue
                text = str(item).strip()
                if text:
                    normalised.append(text)
            return normalised
        return []

    def _as_bool(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def _missing_tools(self, commands: List[str]) -> List[str]:
        missing: List[str] = []
        for command in commands:
            if command == "netstat -tulpen":
                if not (self._verify_tool("netstat") or self._verify_tool("ss")):
                    missing.append("netstat/ss")
                continue

            tool = ALLOWED_COMMANDS.get(command, [None])[0]
            if tool and not self._verify_tool(tool):
                missing.append(tool)

        return sorted(dict.fromkeys(missing))

    def _planned_directory(self, timestamp: str) -> Path:
        slug = re.sub(r"[^0-9A-Za-z]+", "_", timestamp).strip("_")
        if not slug:
            from ...core.time_utils import utc_slug  # Local import to avoid cycle.

            slug = utc_slug()
        return self.case_dir / "acq" / "live" / slug

    def _planned_steps(self, commands: List[str], directory: Path) -> List[str]:
        steps: List[str] = []
        for command in commands:
            execution = self._resolve_execution(command)
            display = execution[1] if execution else "missing tool"
            safe_name = self._safe_filename(command)
            steps.append(
                f"{display} -> {directory / (safe_name + '.out')} / {directory / (safe_name + '.err')}"
            )
        return steps

    def _resolve_execution(self, command: str) -> Optional[tuple[List[str], str]]:
        if command not in ALLOWED_COMMANDS:
            return None

        if command == "netstat -tulpen":
            if self._verify_tool("netstat"):
                return (ALLOWED_COMMANDS[command], "netstat -tulpen")
            if self._verify_tool("ss"):
                return (["ss", "-tulpen"], "ss -tulpen")
            return None

        argv = ALLOWED_COMMANDS[command]
        if not self._verify_tool(argv[0]):
            return None
        return (argv, " ".join(argv))

    def _safe_filename(self, command: str) -> str:
        return re.sub(r"[^0-9A-Za-z._-]+", "_", command).strip("_") or "command"

    def _log_chain_of_custody(
        self,
        meta_path: Path,
        meta_sha: str,
        command_records: List[Dict[str, Any]],
        hashes: List[Dict[str, str]],
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
                description="Live response outputs collected.",
                metadata={
                    "metadata_file": str(meta_path),
                    "metadata_sha256": meta_sha,
                    "commands": [
                        {
                            "requested": record["requested"],
                            "executed": record["executed"],
                            "stdout_path": record["stdout_path"],
                            "stdout_sha256": record["stdout_sha256"],
                            "stderr_path": record["stderr_path"],
                            "stderr_sha256": record["stderr_sha256"],
                        }
                        for record in command_records
                    ],
                    "hashes": hashes,
                },
                integrity_hash=meta_sha,
            )
        except Exception:  # pragma: no cover - best effort logging only
            self.logger.warning("Failed to log live response to chain of custody.")


__all__ = ["LiveResponseModule"]
