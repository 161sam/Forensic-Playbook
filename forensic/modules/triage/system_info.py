"""System information triage module with guarded, deterministic output."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ...core.evidence import Evidence
from ...core.module import ModuleResult, TriageModule
from ...utils import io

DEFAULT_FIELDS: Tuple[str, ...] = (
    "os",
    "kernel",
    "hostname",
    "timezone",
    "interfaces",
    "mounts",
)


@dataclass(frozen=True)
class FieldInfo:
    """Descriptor for supported system information fields."""

    key: str
    description: str


FIELD_DESCRIPTORS: Dict[str, FieldInfo] = {
    "os": FieldInfo("os", "Operating system metadata"),
    "kernel": FieldInfo("kernel", "Kernel release information"),
    "hostname": FieldInfo("hostname", "Hostname and FQDN"),
    "timezone": FieldInfo("timezone", "System timezone"),
    "interfaces": FieldInfo("interfaces", "Network interfaces"),
    "mounts": FieldInfo("mounts", "Mounted filesystems"),
}

FIELD_ALIASES: Dict[str, str] = {
    "os": "os",
    "operating_system": "os",
    "kernel": "kernel",
    "hostname": "hostname",
    "fqdn": "hostname",
    "timezone": "timezone",
    "tz": "timezone",
    "interfaces": "interfaces",
    "network_interfaces": "interfaces",
    "mounts": "mounts",
    "filesystems": "mounts",
}


class SystemInfoModule(TriageModule):
    """Collect read-only system information driven by configuration."""

    @property
    def name(self) -> str:
        return "system_info"

    @property
    def description(self) -> str:
        return "Gather host OS, kernel, timezone and environment metadata"

    def _config_defaults(self) -> Dict[str, Any]:
        return self._module_config("triage", "system_info")

    def validate_params(self, params: Dict) -> bool:
        defaults = self._config_defaults()
        requested = params.get("fields", defaults.get("fields", DEFAULT_FIELDS))
        fields = self._normalise_fields(requested)

        if not fields:
            self.logger.error("No system information fields requested.")
            return False

        unknown = [field for field in fields if field not in FIELD_DESCRIPTORS]
        if unknown:
            self.logger.error(
                "Unsupported system information fields requested: %s",
                ", ".join(sorted(unknown)),
            )
            return False

        params["fields"] = fields
        params["dry_run"] = self._to_bool(
            params.get("dry_run", defaults.get("dry_run", False))
        )
        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        del evidence  # System information is gathered from the local host.

        result_id = self._generate_result_id()
        timestamp = self.current_timestamp()
        defaults = self._config_defaults()

        requested_fields = params.get("fields", defaults.get("fields", DEFAULT_FIELDS))
        fields = self._normalise_fields(requested_fields)

        if not fields:
            return self.guard_result(
                "No valid system information fields were provided.",
                hints=[
                    "Update triage.system_info.fields to include supported entries."
                ],
                metadata={"fields": []},
                result_id=result_id,
                timestamp=timestamp,
            )

        unknown = [field for field in fields if field not in FIELD_DESCRIPTORS]
        if unknown:
            return self.guard_result(
                "Encountered unsupported system information fields.",
                hints=[
                    "Remove invalid fields from triage.system_info.fields",
                    f"Unsupported: {', '.join(sorted(unknown))}",
                ],
                metadata={"fields": fields, "unsupported": sorted(unknown)},
                result_id=result_id,
                timestamp=timestamp,
            )

        dry_run = self._to_bool(params.get("dry_run", defaults.get("dry_run", False)))

        planned_dir = self._planned_directory(timestamp)
        output_path = planned_dir / "system.json"
        planned_steps = [
            f"Collect {FIELD_DESCRIPTORS[field].description} -> {output_path}"
            for field in fields
        ]

        if dry_run:
            metadata = {
                "fields": fields,
                "planned_directory": str(planned_dir),
            }
            metadata.update(self.dry_run_notice(planned_steps))
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="success",
                timestamp=timestamp,
                findings=[
                    {
                        "type": "dry_run",
                        "description": "Dry-run only planned system information collection.",
                        "fields": fields,
                    }
                ],
                metadata=metadata,
                errors=[],
            )

        snapshot: Dict[str, Any] = {
            "module": self.name,
            "collected_at": timestamp,
            "fields": fields,
        }

        errors: List[str] = []

        for field in fields:
            collector = getattr(self, f"_collect_{field}")
            value, error = collector()
            if value is not None:
                snapshot[field] = value
            if error:
                errors.append(error)

        planned_dir.mkdir(parents=True, exist_ok=True)
        io.write_json(output_path, snapshot)

        status = "success" if not errors else "partial"

        findings = [
            {
                "type": "system_info",
                "description": "System information snapshot collected.",
                "fields": fields,
                "output": str(output_path),
            }
        ]

        metadata = {
            "fields": fields,
            "artifacts": [str(output_path)],
        }
        if errors:
            metadata["collection_warnings"] = errors

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

    # ------------------------------------------------------------------
    # Collection helpers
    # ------------------------------------------------------------------

    def _collect_os(self) -> Tuple[Dict[str, Any], Optional[str]]:
        release_path = Path("/etc/os-release")
        if not release_path.exists():
            return (
                {
                    "name": self._platform_system(),
                },
                "os-release file not found; limited OS metadata collected.",
            )

        info: Dict[str, Any] = {}
        for line in release_path.read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip().lower()
            value = value.strip().strip('"')
            info[key] = value

        result = {
            "name": info.get("pretty_name")
            or info.get("name")
            or self._platform_system(),
            "id": info.get("id"),
            "version": info.get("version_id"),
            "build": info.get("build_id"),
        }

        return (result, None)

    def _collect_kernel(self) -> Tuple[Dict[str, Any], Optional[str]]:
        import platform

        uname = platform.uname()
        result = {
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
        }
        return (result, None)

    def _collect_hostname(self) -> Tuple[Dict[str, Any], Optional[str]]:
        import socket

        hostname = socket.gethostname()
        fqdn = socket.getfqdn()
        return ({"hostname": hostname, "fqdn": fqdn}, None)

    def _collect_timezone(self) -> Tuple[Dict[str, Any], Optional[str]]:
        now = datetime.now().astimezone()
        tzname = now.tzname() or "Unknown"
        offset = now.strftime("%z")
        return ({"name": tzname, "offset": offset}, None)

    def _collect_interfaces(self) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        base = Path("/sys/class/net")
        if not base.exists():
            return ([], "Network interface directory /sys/class/net not found.")

        entries: List[Dict[str, Any]] = []

        for iface_path in sorted(base.iterdir(), key=lambda item: item.name):
            if not iface_path.is_dir():
                continue

            info: Dict[str, Any] = {"name": iface_path.name}
            mac_path = iface_path / "address"
            state_path = iface_path / "operstate"
            mtu_path = iface_path / "mtu"

            if mac_path.exists():
                info["mac"] = mac_path.read_text(
                    encoding="utf-8", errors="ignore"
                ).strip()
            if state_path.exists():
                info["state"] = state_path.read_text(
                    encoding="utf-8", errors="ignore"
                ).strip()
            if mtu_path.exists():
                try:
                    info["mtu"] = int(
                        mtu_path.read_text(encoding="utf-8", errors="ignore").strip()
                    )
                except ValueError:
                    info["mtu"] = mtu_path.read_text(
                        encoding="utf-8", errors="ignore"
                    ).strip()

            entries.append(info)

        return (entries, None)

    def _collect_mounts(self) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        mounts_path = Path("/proc/mounts")
        if not mounts_path.exists():
            return ([], "/proc/mounts not available; mount information unavailable.")

        records: List[Dict[str, Any]] = []
        for line in mounts_path.read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            device, mount_point, fs_type = parts[:3]
            options = parts[3] if len(parts) > 3 else ""
            record: Dict[str, Any] = {
                "device": device,
                "mount_point": mount_point,
                "filesystem": fs_type,
            }
            if options:
                record["options"] = sorted(opt for opt in options.split(",") if opt)
            records.append(record)

        records.sort(key=lambda item: item["mount_point"])
        return (records, None)

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _normalise_fields(self, raw: Any) -> List[str]:
        items: Iterable[Any]
        if isinstance(raw, str):
            items = [segment.strip() for segment in raw.split(",")]
        elif isinstance(raw, Iterable):
            items = raw
        else:
            return []

        resolved: List[str] = []
        for item in items:
            if item is None:
                continue
            key = str(item).strip()
            if not key:
                continue
            normalised = self._normalise_field_name(key)
            if normalised and normalised not in resolved:
                resolved.append(normalised)
        return resolved

    def _normalise_field_name(self, name: str) -> Optional[str]:
        lowered = name.strip().lower().replace(" ", "_")
        if lowered in FIELD_DESCRIPTORS:
            return lowered
        return FIELD_ALIASES.get(lowered)

    def _to_bool(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
        return bool(value)

    def _planned_directory(self, timestamp: str) -> Path:
        slug = re.sub(r"[^0-9A-Za-z]+", "_", timestamp).strip("_")
        if not slug:
            from ...core.time_utils import utc_slug  # Local import to avoid cycles.

            slug = utc_slug()
        return self.case_dir / "triage" / self.name / slug

    def _platform_system(self) -> str:
        import platform

        return platform.system()


__all__ = ["SystemInfoModule"]
