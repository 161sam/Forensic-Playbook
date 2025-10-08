"""Persistence hunting module."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from ...core.evidence import Evidence
from ...core.module import ModuleResult, TriageModule
from ...utils import io, timefmt

TARGETS = {
    "systemd": Path("/etc/systemd/system"),
    "cron": Path("/etc/crontab"),
    "cron_hourly": Path("/etc/cron.hourly"),
    "rc_local": Path("/etc/rc.local"),
    "autostart": Path("/etc/xdg/autostart"),
}


class PersistenceModule(TriageModule):
    """Enumerate potential persistence mechanisms in a read-only fashion."""

    @property
    def name(self) -> str:
        return "persistence"

    @property
    def description(self) -> str:
        return "List common persistence artefacts"

    def validate_params(self, params: Dict) -> bool:  # pragma: no cover - trivial
        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        result_id = self._generate_result_id()
        timestamp = timefmt.utcnow_iso()

        findings: List[Dict[str, str]] = []
        metadata: Dict[str, List[str]] = {}
        errors: List[str] = []

        for label, path in TARGETS.items():
            if path.is_file():
                findings.append(
                    {
                        "type": "persistence_file",
                        "description": f"{label} configuration present",
                        "path": str(path),
                    }
                )
                metadata[label] = ["file"]
                continue

            if path.is_dir():
                entries = sorted(p.name for p in path.iterdir())
                metadata[label] = entries
                if entries:
                    findings.append(
                        {
                            "type": "persistence_directory",
                            "description": f"{label} contains entries",
                            "path": str(path),
                            "count": str(len(entries)),
                        }
                    )
            else:
                errors.append(f"Path not found: {path}")

        output_file = self.output_dir / "persistence.json"
        io.write_json(output_file, {"findings": findings, "metadata": metadata})

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


__all__ = ["PersistenceModule"]
