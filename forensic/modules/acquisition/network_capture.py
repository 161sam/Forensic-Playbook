"""Network capture module with dry-run capability."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from ...core.evidence import Evidence
from ...core.module import AcquisitionModule, ModuleResult

CAPTURE_TOOLS = ("tcpdump", "dumpcap")


class NetworkCaptureModule(AcquisitionModule):
    """Capture live network traffic into PCAP files."""

    @property
    def name(self) -> str:
        return "network_capture"

    @property
    def description(self) -> str:
        return "Capture network packets with tcpdump/dumpcap"

    @property
    def requires_root(self) -> bool:
        return True

    def validate_params(self, params: Dict) -> bool:
        params.setdefault("duration", 300)
        params.setdefault("interface", "eth0")
        params.setdefault("tool", "tcpdump")
        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        result_id = self._generate_result_id()
        timestamp = datetime.utcnow().isoformat() + "Z"
        duration = int(params.get("duration", 300))
        interface = params.get("interface", "eth0")
        output = Path(params.get("output", self.output_dir / "capture.pcap"))
        tool = params.get("tool", "tcpdump")

        if tool not in CAPTURE_TOOLS:
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=[],
                metadata={"interface": interface},
                errors=[f"Unsupported tool: {tool}"],
            )

        if not self._verify_tool(tool):
            guidance = f"Tool '{tool}' not found. Install tcpdump or dumpcap to use network capture."
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="skipped",
                timestamp=timestamp,
                findings=[],
                metadata={"interface": interface, "tool": tool},
                errors=[guidance],
            )

        if params.get("dry_run", False):
            message = f"Dry-run: would execute {tool} on interface {interface} for {duration}s"
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="success",
                timestamp=timestamp,
                output_path=None,
                findings=[{"description": message, "type": "dry_run"}],
                metadata={"interface": interface, "tool": tool, "dry_run": True},
                errors=[],
            )

        guidance = (
            f"Detected {tool} but live capture is disabled in automated runs. "
            "Execute manually with appropriate permissions."
        )
        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status="partial",
            timestamp=timestamp,
            output_path=output,
            findings=[
                {
                    "type": "notice",
                    "description": "Network capture not executed to avoid side effects",
                }
            ],
            metadata={
                "interface": interface,
                "tool": tool,
                "planned_output": str(output),
                "duration": duration,
            },
            errors=[guidance],
        )


__all__ = ["NetworkCaptureModule"]
