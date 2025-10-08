"""System information triage module."""

from __future__ import annotations

import os
import platform
import socket
from datetime import datetime
from typing import Dict, Optional

from ...core.evidence import Evidence
from ...core.module import ModuleResult, TriageModule
from ...utils import io, timefmt


class SystemInfoModule(TriageModule):
    """Collect basic host information without modifying the system."""

    @property
    def name(self) -> str:
        return "system_info"

    @property
    def description(self) -> str:
        return "Gather hostname, OS, timezone and environment metadata"

    def validate_params(self, params: Dict) -> bool:  # pragma: no cover - trivial
        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        result_id = self._generate_result_id()
        timestamp = timefmt.utcnow_iso()

        snapshot = {
            "collected_at": timestamp,
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "platform": platform.platform(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python": platform.python_version(),
            "timezone": datetime.now().astimezone().tzname(),
            "environment": {
                k: v for k, v in os.environ.items() if k.startswith("LANG")
            },
        }

        output_file = self.output_dir / "system_info.json"
        io.write_json(output_file, snapshot)

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status="success",
            timestamp=timestamp,
            output_path=output_file,
            findings=[
                {
                    "type": "system_info",
                    "description": "System metadata captured",
                    "hostname": snapshot["hostname"],
                }
            ],
            metadata={"fields": list(snapshot.keys())},
            errors=[],
        )


__all__ = ["SystemInfoModule"]
