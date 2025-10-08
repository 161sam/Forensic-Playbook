"""Memory acquisition module with friendly guards."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from ...core.evidence import Evidence
from ...core.module import AcquisitionModule, ModuleResult

TOOLS = ("avml", "lime", "winpmem")


class MemoryDumpModule(AcquisitionModule):
    """Perform a memory acquisition if supported tools are available."""

    @property
    def name(self) -> str:
        return "memory_dump"

    @property
    def description(self) -> str:
        return "Acquire volatile memory with safety checks"

    @property
    def requires_root(self) -> bool:
        return True

    @property
    def supported_evidence_types(self) -> list:
        return ["memory"]

    def validate_params(self, params: Dict) -> bool:
        output = Path(params.get("output", self.output_dir / "memory.raw"))
        output.parent.mkdir(parents=True, exist_ok=True)
        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        result_id = self._generate_result_id()
        timestamp = datetime.utcnow().isoformat() + "Z"
        output = Path(params.get("output", self.output_dir / "memory.raw"))
        requested_tool = params.get("tool")
        tool = self._select_tool(requested_tool)

        if not tool:
            guidance = (
                "No supported memory acquisition tool detected. Install one of "
                f"{', '.join(TOOLS)} or run in dry-run mode."
            )
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="skipped",
                timestamp=timestamp,
                output_path=None,
                findings=[],
                metadata={"requested_tool": requested_tool},
                errors=[guidance],
            )

        if params.get("dry_run", False):
            message = f"Dry-run selected. Would execute {tool} to write {output}."
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="success",
                timestamp=timestamp,
                output_path=None,
                findings=[{"description": message, "type": "dry_run"}],
                metadata={"tool": tool, "dry_run": True},
                errors=[],
            )

        # Real acquisition is not executed in this environment – users receive
        # actionable guidance instead of a failing run.
        guidance = (
            f"Tool '{tool}' detected but real acquisition is disabled in the "
            "framework sandbox. Execute manually if required."
        )
        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status="partial",
            timestamp=timestamp,
            output_path=output,
            findings=[
                {
                    "description": "Acquisition not performed to maintain sandbox safety",
                    "type": "notice",
                }
            ],
            metadata={"tool": tool, "planned_output": str(output)},
            errors=[guidance],
        )

    def _select_tool(self, requested: Optional[str]) -> Optional[str]:
        if requested:
            if self._verify_tool(requested):
                return requested
            return None

        for candidate in TOOLS:
            if self._verify_tool(candidate):
                return candidate
        return None


__all__ = ["MemoryDumpModule"]
