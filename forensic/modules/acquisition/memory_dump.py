"""Guarded memory acquisition module."""

from __future__ import annotations

import json
import platform
import shutil
import socket
from pathlib import Path
from typing import Dict, Optional

from ...core.chain_of_custody import ChainOfCustody
from ...core.evidence import Evidence
from ...core.module import AcquisitionModule, ModuleResult
from ...core.time_utils import utc_isoformat, utc_slug


class MemoryDumpModule(AcquisitionModule):
    """Acquire volatile memory using platform-specific tooling."""

    def __init__(self, case_dir: Path, config: Dict):
        super().__init__(case_dir=case_dir, config=config)
        # Store acquisitions under ``<case>/acq/memdump`` instead of the
        # default analysis directory.
        self.output_dir = self.case_dir / "acq" / "memdump"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @property
    def name(self) -> str:
        return "memory_dump"

    @property
    def description(self) -> str:
        return "Acquire volatile memory from the current system"

    @property
    def requires_root(self) -> bool:
        # Memory capture requires elevated privileges on Linux hosts.
        return platform.system().lower() == "linux"

    @property
    def supported_evidence_types(self) -> list[str]:
        return ["memory"]

    def validate_params(self, params: Dict) -> bool:
        # No strict parameter requirements besides the live-capture guard. The
        # guard itself is handled inside :meth:`run` so that we can produce a
        # friendly error instead of a generic validation failure.
        params.setdefault("dry_run", False)
        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        del evidence  # Memory acquisition operates on the local host only.

        result_id = self._generate_result_id()
        timestamp = utc_isoformat()
        dry_run = bool(params.get("dry_run", False))
        enable_live_capture = bool(params.get("enable_live_capture", False))

        if not enable_live_capture:
            message = (
                "Live acquisition is disabled. Re-run with --enable-live-capture "
                "to confirm intentional memory dumping."
            )
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="skipped",
                timestamp=timestamp,
                findings=[],
                metadata={"enable_live_capture": enable_live_capture},
                errors=[message],
            )

        system = platform.system().lower()
        if system == "windows":
            message = (
                "Windows memory capture is not automated. Use winpmem manually "
                "and import the resulting image into the case."
            )
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="skipped",
                timestamp=timestamp,
                findings=[],
                metadata={"platform": system, "recommended_tool": "winpmem"},
                errors=[message],
            )

        if system != "linux":
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="skipped",
                timestamp=timestamp,
                findings=[],
                metadata={"platform": system},
                errors=["Memory acquisition is only supported on Linux hosts."],
            )

        if not self._verify_tool("avml"):
            guidance = (
                "avml is not available in the environment. Install Microsoft's AVML "
                "utility or perform the capture manually."
            )
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="skipped",
                timestamp=timestamp,
                findings=[],
                metadata={"platform": system, "missing_tools": ["avml"]},
                errors=[guidance],
            )

        avml_path = shutil.which("avml") or "avml"

        hostname = params.get("hostname") or socket.gethostname() or "localhost"
        slug = utc_slug()
        base_name = f"{hostname}_{slug}"
        output_path = self._ensure_unique_path(self.output_dir / f"{base_name}.raw")
        meta_path = output_path.with_name(f"{output_path.stem}.meta.json")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        command = [avml_path, str(output_path)]
        metadata = {
            "platform": system,
            "tool": "avml",
            "tool_path": avml_path,
            "command": command,
            "hostname": hostname,
            "timestamp": timestamp,
            "dry_run": dry_run,
            "output": str(output_path),
        }

        if dry_run:
            findings = [
                {
                    "type": "dry_run",
                    "description": "Dry-run enabled. Capture command prepared.",
                    "command": " ".join(command),
                    "output": str(output_path),
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

        try:
            stdout, stderr, returncode = self._run_command(
                command, timeout=params.get("timeout", 1800)
            )
        except Exception as exc:  # pragma: no cover - subprocess errors surface here
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=[],
                metadata=metadata,
                errors=[f"Failed to execute avml: {exc}"],
            )

        metadata.update(
            {
                "returncode": returncode,
                "stdout": stdout,
                "stderr": stderr,
            }
        )

        if returncode != 0 or not output_path.exists():
            error_message = (
                "avml did not complete successfully. Review stdout/stderr for details."
            )
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=[],
                metadata=metadata,
                errors=[error_message],
            )

        hash_value = self._stream_sha256(output_path)
        metadata["sha256"] = hash_value
        metadata["size_bytes"] = output_path.stat().st_size

        meta_path = self._ensure_unique_meta(meta_path)
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        self._log_chain_of_custody(hash_value, output_path, meta_path)

        findings = [
            {
                "type": "memory_acquisition",
                "description": f"Memory captured to {output_path.name}",
                "hash_sha256": hash_value,
                "size_bytes": metadata["size_bytes"],
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

    def _ensure_unique_path(self, path: Path) -> Path:
        """Return a unique path by appending a numeric suffix if necessary."""

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

    def _stream_sha256(self, file_path: Path) -> str:
        import hashlib

        hasher = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _log_chain_of_custody(
        self, hash_value: str, output_path: Path, meta_path: Path
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
                description=f"Memory dump created: {output_path.name}",
                metadata={
                    "path": str(output_path),
                    "metadata_file": str(meta_path),
                    "hash_sha256": hash_value,
                    "tool": "avml",
                },
                integrity_hash=hash_value,
            )
        except Exception:  # pragma: no cover - best-effort logging
            self.logger.warning("Failed to log memory acquisition to chain of custody.")


__all__ = ["MemoryDumpModule"]
