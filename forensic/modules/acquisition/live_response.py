"""Live response collection module."""

from __future__ import annotations

import platform
import subprocess
from typing import Dict, List, Optional

from ...core.evidence import Evidence
from ...core.module import AcquisitionModule, ModuleResult
from ...core.time_utils import utc_isoformat
from ...utils import io

COMMANDS = {
    "uname": ["uname", "-a"],
    "processes": ["ps", "aux"],
    "network": ["netstat", "-tulpen"],
    "mounts": ["mount"],
}


class LiveResponseModule(AcquisitionModule):
    """Collect a minimal live response snapshot."""

    @property
    def name(self) -> str:
        return "live_response"

    @property
    def description(self) -> str:
        return "Collect host metadata and volatile artefacts"

    @property
    def requires_root(self) -> bool:
        return False

    def validate_params(self, params: Dict) -> bool:
        params.setdefault("commands", list(COMMANDS.keys()))
        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        result_id = self._generate_result_id()
        timestamp = utc_isoformat()
        commands = params.get("commands", list(COMMANDS.keys()))
        output_dir = self.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        findings = [
            {
                "type": "system_info",
                "description": "Live response snapshot created",
                "platform": platform.platform(),
            }
        ]

        metadata: Dict[str, List[str]] = {"executed": []}
        errors: List[str] = []

        snapshot = {
            "collected_at": timestamp,
            "platform": platform.platform(),
        }

        for command_name in commands:
            cmd = COMMANDS.get(command_name)
            if not cmd:
                errors.append(f"Unknown command requested: {command_name}")
                continue
            metadata.setdefault("commands", []).append(" ".join(cmd))

            if not self._verify_tool(cmd[0]):
                errors.append(f"Skipping {command_name}: tool '{cmd[0]}' not available")
                continue

            try:
                completed = subprocess.run(
                    cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                snapshot[command_name] = {
                    "stdout": completed.stdout.strip(),
                    "stderr": completed.stderr.strip(),
                    "returncode": completed.returncode,
                }
                metadata["executed"].append(command_name)
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(f"Failed to run {command_name}: {exc}")

        output_file = output_dir / "live_response.json"
        io.write_json(output_file, snapshot)

        status = "success" if not errors else "partial"

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=output_file,
            findings=findings,
            metadata=metadata,
            errors=errors,
        )


__all__ = ["LiveResponseModule"]
