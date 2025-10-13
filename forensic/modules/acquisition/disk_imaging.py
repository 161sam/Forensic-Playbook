"""Guarded disk imaging module with deterministic artefacts."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ...core.chain_of_custody import ChainOfCustody
from ...core.evidence import Evidence
from ...core.module import AcquisitionModule, ModuleResult
from ...core.time_utils import utc_isoformat, utc_slug

SUPPORTED_TOOLS = {"dd", "ddrescue", "ewfacquire"}
SUPPORTED_HASHES = {"sha256", "sha1", "md5"}


class DiskImagingModule(AcquisitionModule):
    """Perform guarded disk imaging with optional verification."""

    def __init__(self, case_dir: Path, config: Dict):
        super().__init__(case_dir=case_dir, config=config)
        self.output_dir = self.case_dir / "acq" / "disk"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._param_sources: Dict[str, str] = {}

    @property
    def name(self) -> str:
        return "disk_imaging"

    @property
    def description(self) -> str:
        return "Forensic disk imaging with verification"

    @property
    def requires_root(self) -> bool:
        return True

    @property
    def supported_evidence_types(self) -> List[str]:
        return ["disk", "partition"]

    def validate_params(self, params: Dict) -> bool:
        defaults = self._config_defaults()
        original = dict(params)
        resolved: Dict[str, Any] = {}
        self._param_sources = {}

        def _resolve(key: str, *, default: Any = None) -> Any:
            if key in original and original[key] not in (None, ""):
                resolved[key] = original[key]
                self._param_sources[key] = "cli"
                return resolved[key]

            if key in defaults and defaults[key] not in (None, ""):
                resolved[key] = defaults[key]
                self._param_sources[key] = "config"
                return resolved[key]

            resolved[key] = default
            self._param_sources[key] = "default"
            return default

        _resolve("source")
        _resolve("tool", default="ddrescue")
        _resolve("hash_algorithm", default="sha256")
        _resolve("block_size", default="4M")
        _resolve("skip_verify", default=False)
        _resolve("dry_run", default=False)
        _resolve("force", default=False)
        _resolve("output")
        _resolve("allow_file_source", default=False)

        params.clear()
        params.update(resolved)
        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        del evidence

        timestamp = utc_isoformat()
        slug = utc_slug()
        result_id = self._generate_result_id()
        parameter_sources = dict(getattr(self, "_param_sources", {}))

        def _as_bool(value: Any) -> bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in {"1", "true", "yes", "on"}:
                    return True
                if lowered in {"0", "false", "no", "off"}:
                    return False
            return bool(value)

        dry_run = _as_bool(params.get("dry_run", False))
        skip_verify = _as_bool(params.get("skip_verify", False))
        force = _as_bool(params.get("force", False))
        allow_file_source = _as_bool(params.get("allow_file_source", False))

        source_value = params.get("source")
        if not source_value:
            metadata = {"parameter_sources": parameter_sources}
            return self.guard_result(
                "No source device provided for imaging.",
                hints=["Specify --param source=/dev/sdX to choose the device."],
                status="failed",
                metadata=metadata,
                result_id=result_id,
                timestamp=timestamp,
            )

        source_path = Path(str(source_value))
        if not source_path.exists():
            metadata = {
                "source": str(source_path),
                "parameter_sources": parameter_sources,
            }
            return self.guard_result(
                f"Source path not found: {source_path}",
                hints=["Verify the device path and ensure it is accessible."],
                status="failed",
                metadata=metadata,
                result_id=result_id,
                timestamp=timestamp,
            )

        if not self._is_block_device(source_path):
            if not (allow_file_source and source_path.is_file()):
                metadata = {
                    "source": str(source_path),
                    "parameter_sources": parameter_sources,
                }
                hints = [
                    "Imaging expects a block device (e.g. /dev/sdb).",
                    "Pass --param allow_file_source=true to operate on regular files.",
                ]
                return self.guard_result(
                    "Source path is not a block device.",
                    hints=hints,
                    status="failed",
                    metadata=metadata,
                    result_id=result_id,
                    timestamp=timestamp,
                )

        tool = str(params.get("tool") or "ddrescue").strip().lower()
        if tool not in SUPPORTED_TOOLS:
            metadata = {
                "tool": tool,
                "supported_tools": sorted(SUPPORTED_TOOLS),
                "parameter_sources": parameter_sources,
            }
            return self.guard_result(
                f"Unsupported imaging tool requested: {tool}",
                hints=["Choose one of dd, ddrescue, or ewfacquire."],
                status="failed",
                metadata=metadata,
                result_id=result_id,
                timestamp=timestamp,
            )

        hash_algorithm = str(params.get("hash_algorithm") or "sha256").lower()
        if hash_algorithm not in SUPPORTED_HASHES:
            metadata = {
                "hash_algorithm": hash_algorithm,
                "supported": sorted(SUPPORTED_HASHES),
                "parameter_sources": parameter_sources,
            }
            return self.guard_result(
                "Unsupported hash algorithm requested.",
                hints=["Select sha256, sha1, or md5."],
                status="failed",
                metadata=metadata,
                result_id=result_id,
                timestamp=timestamp,
            )

        block_size = str(params.get("block_size") or "4M")

        try:
            output_path, meta_path = self._resolve_output_paths(
                params.get("output"), slug, source_path.name or "disk", tool
            )
        except ValueError as exc:
            metadata = {
                "source": str(source_path),
                "requested_output": params.get("output"),
                "parameter_sources": parameter_sources,
            }
            return self.guard_result(
                str(exc),
                hints=["Outputs must remain within the case directory."],
                status="failed",
                metadata=metadata,
                result_id=result_id,
                timestamp=timestamp,
            )

        metadata_base = {
            "timestamp": timestamp,
            "source": str(source_path),
            "tool": tool,
            "hash_algorithm": hash_algorithm,
            "block_size": block_size,
            "skip_verify": skip_verify,
            "dry_run": dry_run,
            "output": str(output_path),
            "metadata_file": str(meta_path),
            "parameter_sources": parameter_sources,
            "force": force,
            "allow_file_source": allow_file_source,
        }

        if output_path.exists() and not force:
            hints = [
                "Specify --param force=true to overwrite the existing image.",
                f"Existing file: {output_path}",
            ]
            return self.guard_result(
                "Output image already exists.",
                hints=hints,
                status="failed",
                metadata=metadata_base,
                result_id=result_id,
                timestamp=timestamp,
            )

        tool_available = self._verify_tool(tool)

        planned_steps = self._planned_steps(
            tool,
            source_path,
            output_path,
            hash_algorithm,
            skip_verify,
        )

        if dry_run:
            metadata = self.dry_run_notice(planned_steps)
            metadata.update(metadata_base)
            if not tool_available:
                guard = self.guard_result(
                    f"Required imaging tool missing: {tool}",
                    hints=[f"Install {tool} or adjust the configured tool."],
                    status="partial",
                    metadata=metadata,
                    result_id=result_id,
                    timestamp=timestamp,
                )
                guard.errors.append(
                    "Dry-run detected missing tooling. No imaging executed."
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
                        "description": "Prepared disk imaging command.",
                        "tool": tool,
                        "output": str(output_path),
                    }
                ],
                metadata=metadata,
                errors=[],
            )

        if not tool_available:
            metadata = metadata_base | {"missing_tools": [tool]}
            return self.guard_result(
                f"Required imaging tool missing: {tool}",
                hints=[f"Install {tool} or switch to an available tool."],
                status="skipped",
                metadata=metadata,
                result_id=result_id,
                timestamp=timestamp,
            )

        output_path.parent.mkdir(parents=True, exist_ok=True)

        imaging_metadata: Dict[str, Any] = {}
        commands: List[Sequence[str]] = []
        errors: List[str] = []

        try:
            if tool == "dd":
                success, tool_meta, executed = self._image_with_dd(
                    source_path, output_path, block_size
                )
            elif tool == "ddrescue":
                success, tool_meta, executed = self._image_with_ddrescue(
                    source_path, output_path
                )
            else:
                success, tool_meta, executed = self._image_with_ewfacquire(
                    source_path, output_path
                )
        except Exception as exc:
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=[],
                metadata=metadata_base,
                errors=[f"Imaging command failed: {exc}"],
            )

        imaging_metadata.update(tool_meta)
        commands.extend(executed)

        if not success or not output_path.exists():
            errors.append("Imaging command did not complete successfully.")
            status = "failed"
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status=status,
                timestamp=timestamp,
                findings=[],
                metadata=metadata_base | imaging_metadata,
                errors=errors,
            )

        metadata_base["size_bytes"] = output_path.stat().st_size

        source_hash: Optional[str] = None
        if not skip_verify:
            try:
                source_hash = self._hash_device(source_path, hash_algorithm)
                imaging_metadata["source_hash"] = source_hash
            except Exception as exc:
                errors.append(f"Failed to compute source hash: {exc}")

        image_hash: Optional[str] = None
        try:
            image_hash = self._compute_hash(output_path, hash_algorithm)
            imaging_metadata["image_hash"] = image_hash
        except Exception as exc:
            errors.append(f"Failed to compute image hash: {exc}")

        hash_entries: List[Dict[str, str]] = []
        if source_hash:
            hash_entries.append(
                {
                    "path": str(source_path),
                    "algorithm": hash_algorithm,
                    "value": source_hash,
                }
            )
        if image_hash:
            hash_entries.append(
                {
                    "path": str(output_path),
                    "algorithm": hash_algorithm,
                    "value": image_hash,
                }
            )

        hash_file = output_path.with_suffix(output_path.suffix + f".{hash_algorithm}")
        if image_hash:
            hash_file.write_text(
                f"{image_hash}  {output_path.name}\n", encoding="utf-8"
            )
            imaging_metadata["hash_file"] = str(hash_file)
            hash_entries.append(
                {
                    "path": str(hash_file),
                    "algorithm": hash_algorithm,
                    "value": image_hash,
                }
            )

        meta_document = {
            "module": self.name,
            "timestamp": timestamp,
            "source": str(source_path),
            "output": str(output_path),
            "tool": tool,
            "commands": [" ".join(cmd) for cmd in commands],
            "hash_algorithm": hash_algorithm,
            "hashes": hash_entries,
            "skip_verify": skip_verify,
            "parameter_sources": parameter_sources,
        }
        if block_size:
            meta_document["block_size"] = block_size
        if imaging_metadata:
            meta_document["tool_metadata"] = imaging_metadata

        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(
            json.dumps(meta_document, indent=2, sort_keys=True), encoding="utf-8"
        )

        meta_hash = self._compute_hash(meta_path, "sha256")
        hash_entries.append(
            {
                "path": str(meta_path),
                "algorithm": "sha256",
                "value": meta_hash,
            }
        )
        hash_entries.sort(key=lambda entry: entry["path"])

        metadata = metadata_base | imaging_metadata
        metadata["hashes"] = hash_entries
        metadata["metadata_sha256"] = meta_hash

        if image_hash:
            self._log_chain_of_custody(
                image_hash,
                output_path,
                meta_path,
                tool,
                hash_file if hash_file.exists() else None,
                hash_algorithm,
                meta_hash,
            )

        findings = [
            {
                "type": "disk_image",
                "description": f"Disk image created at {output_path.name}",
                "tool": tool,
                "hash_algorithm": hash_algorithm,
                "image_hash": image_hash,
                "source_hash": source_hash,
            }
        ]

        status = "success" if not errors else "partial"

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=output_path,
            findings=findings,
            metadata=metadata,
            errors=errors,
        )

    def _config_defaults(self) -> Dict[str, Any]:
        defaults = self._module_config("disk")
        legacy = {k: v for k, v in defaults.items() if k.startswith("default_")}
        if legacy:
            defaults = {**defaults}
            for key, value in legacy.items():
                normalised = key.replace("default_", "")
                defaults.setdefault(normalised, value)
        return defaults

    def _resolve_output_paths(
        self,
        override: Any,
        slug: str,
        source_name: str,
        tool: str,
    ) -> Tuple[Path, Path]:
        if override:
            candidate = Path(str(override))
            if not candidate.is_absolute():
                candidate = (self.case_dir / candidate).resolve()
        else:
            suffix = ".E01" if tool == "ewfacquire" else ".img"
            safe_source = source_name or "disk"
            candidate = (self.output_dir / f"{slug}_{safe_source}{suffix}").resolve()

        case_root = self.case_dir.resolve()
        try:
            candidate.relative_to(case_root)
        except ValueError:
            raise ValueError(
                "Output path must reside inside the case directory."
            ) from None

        meta_path = candidate.with_suffix(candidate.suffix + ".meta.json")
        return candidate, meta_path

    def _planned_steps(
        self,
        tool: str,
        source_path: Path,
        output_path: Path,
        hash_algorithm: str,
        skip_verify: bool,
    ) -> List[str]:
        steps = [
            f"{tool} imaging: {source_path} -> {output_path}",
            f"Write metadata file: {output_path.with_suffix(output_path.suffix + '.meta.json')}",
            f"Compute {hash_algorithm} hash for {output_path}",
        ]
        if not skip_verify:
            steps.insert(1, f"Compute {hash_algorithm} hash of source {source_path}")
        return steps

    def _is_block_device(self, path: Path) -> bool:
        try:
            mode = os.stat(path).st_mode
            return stat.S_ISBLK(mode)
        except OSError:
            return False

    def _image_with_dd(
        self, source: Path, output: Path, block_size: str
    ) -> Tuple[bool, Dict[str, Any], List[Sequence[str]]]:
        command = [
            "dd",
            f"if={source}",
            f"of={output}",
            f"bs={block_size}",
            "conv=sync,noerror",
            "status=progress",
        ]
        stdout, stderr, returncode = self._run_command(command)
        log_file = output.with_suffix(".dd.log")
        log_file.write_text(
            "Command: "
            + " ".join(command)
            + "\n\nSTDOUT:\n"
            + stdout
            + "\n\nSTDERR:\n"
            + stderr,
            encoding="utf-8",
        )
        metadata = {
            "dd_returncode": returncode,
            "dd_log": str(log_file),
        }
        return returncode == 0, metadata, [command]

    def _image_with_ddrescue(
        self, source: Path, output: Path
    ) -> Tuple[bool, Dict[str, Any], List[Sequence[str]]]:
        log_file = output.with_suffix(".ddrescue.log")
        phase1 = ["ddrescue", "-f", "-n", str(source), str(output), str(log_file)]
        stdout1, stderr1, rc1 = self._run_command(phase1)

        phase2 = ["ddrescue", "-f", "-r", "3", str(source), str(output), str(log_file)]
        stdout2, stderr2, rc2 = self._run_command(phase2)

        log_contents = (
            "Phase 1 STDOUT:\n"
            + stdout1
            + "\n\nPhase 1 STDERR:\n"
            + stderr1
            + "\n\nPhase 2 STDOUT:\n"
            + stdout2
            + "\n\nPhase 2 STDERR:\n"
            + stderr2
        )
        log_file.write_text(log_contents, encoding="utf-8")

        metadata = {
            "ddrescue_phase1_returncode": rc1,
            "ddrescue_phase2_returncode": rc2,
            "ddrescue_log": str(log_file),
        }
        return rc2 == 0, metadata, [phase1, phase2]

    def _image_with_ewfacquire(
        self, source: Path, output: Path
    ) -> Tuple[bool, Dict[str, Any], List[Sequence[str]]]:
        output_base = output.with_suffix("")
        command = [
            "ewfacquire",
            "-t",
            str(output_base),
            "-u",
            "-f",
            "encase6",
            str(source),
        ]
        stdout, stderr, returncode = self._run_command(command, timeout=3600)
        log_file = output.with_suffix(".ewf.log")
        log_file.write_text(
            "STDOUT:\n" + stdout + "\n\nSTDERR:\n" + stderr,
            encoding="utf-8",
        )
        metadata = {
            "ewfacquire_returncode": returncode,
            "ewfacquire_log": str(log_file),
            "format": "encase6",
        }
        return returncode == 0, metadata, [command]

    def _hash_device(self, device: Path, algorithm: str) -> str:
        import hashlib

        hasher = getattr(hashlib, algorithm)()
        with device.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _log_chain_of_custody(
        self,
        hash_value: str,
        output_path: Path,
        meta_path: Path,
        tool_name: str,
        hash_file: Optional[Path],
        algorithm: str,
        meta_hash: str,
    ) -> None:
        if not self.config.get("enable_coc", True):
            return

        workspace = self.case_dir.parent.parent
        coc_db = workspace / "chain_of_custody.db"

        try:
            coc = ChainOfCustody(coc_db)
            metadata: Dict[str, Any] = {
                "path": str(output_path),
                "metadata_file": str(meta_path),
                "hash": {"algorithm": algorithm, "value": hash_value},
                "metadata_sha256": meta_hash,
                "tool": tool_name,
            }
            if hash_file is not None:
                metadata["hash_file"] = str(hash_file)

            coc.log_event(
                event_type="EVIDENCE_COLLECTED",
                case_id=self.case_dir.name,
                actor=self.config.get("coc_actor", "Forensic-Playbook"),
                description=f"Disk image created: {output_path.name}",
                metadata=metadata,
                integrity_hash=hash_value,
            )
        except Exception:  # pragma: no cover - best effort logging only
            self.logger.warning("Failed to log disk imaging to chain of custody.")


__all__ = ["DiskImagingModule"]
