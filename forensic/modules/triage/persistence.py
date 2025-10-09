"""Guarded persistence triage module with deterministic outputs."""

from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:  # Python 3.9+
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback when tzdata missing
    ZoneInfo = None  # type: ignore

from ...core.evidence import Evidence
from ...core.module import ModuleResult, TriageModule
from ...utils import io


@dataclass(frozen=True)
class CategoryInfo:
    """Descriptor for supported persistence categories."""

    key: str
    description: str


CATEGORIES: Dict[str, CategoryInfo] = {
    "systemd_units": CategoryInfo("systemd_units", "systemd unit definitions"),
    "cron": CategoryInfo("cron", "Cron schedules"),
    "at": CategoryInfo("at", "at job queues"),
    "rc_local": CategoryInfo("rc_local", "Legacy rc.local scripts"),
    "autostart": CategoryInfo("autostart", "Desktop environment autostarts"),
}


DEFAULT_PATHS: Dict[str, Tuple[str, ...]] = {
    "systemd_units": (
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/system",
    ),
    "cron": (
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
    ),
    "at": (
        "/var/spool/cron/atjobs",
        "/var/spool/cron/atspool",
    ),
    "rc_local": ("/etc/rc.local",),
    "autostart": (
        "/etc/xdg/autostart",
        "~/.config/autostart",
        "~/.local/share/applications",
    ),
}

CSV_HEADERS: Tuple[str, ...] = (
    "category",
    "source",
    "path",
    "name",
    "type",
    "exists",
    "readable",
    "size_bytes",
    "modified",
    "note",
)


class PersistenceModule(TriageModule):
    """Enumerate potential persistence mechanisms in a read-only fashion."""

    @property
    def name(self) -> str:
        return "persistence"

    @property
    def description(self) -> str:
        return "List common persistence artefacts"

    def _config_defaults(self) -> Dict[str, Any]:
        return self._module_config("triage", "persistence")

    def validate_params(self, params: Dict) -> bool:
        defaults = self._config_defaults()
        dry_run = self._to_bool(params.get("dry_run", defaults.get("dry_run", False)))
        params["dry_run"] = dry_run

        configured_paths = params.get("paths", defaults.get("paths", DEFAULT_PATHS))
        path_map = self._normalise_path_map(configured_paths)
        if not path_map:
            self.logger.error("No persistence paths configured.")
            return False

        params["paths"] = path_map
        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        del evidence  # Persistence inspection always targets the live host.

        result_id = self._generate_result_id()
        timestamp = self.current_timestamp()

        defaults = self._config_defaults()
        dry_run = self._to_bool(params.get("dry_run", defaults.get("dry_run", False)))
        path_map = params.get("paths") or self._normalise_path_map(
            defaults.get("paths", DEFAULT_PATHS)
        )

        if not path_map:
            return self.guard_result(
                "No persistence targets configured for inspection.",
                hints=["Populate triage.persistence.paths with directories or files."],
                metadata={"paths": {}},
                result_id=result_id,
                timestamp=timestamp,
            )

        planned_dir = self._planned_directory(timestamp)
        planned_steps = self._plan_steps(path_map)

        if dry_run:
            metadata = {
                "paths": {
                    category: [str(path) for path in paths]
                    for category, paths in path_map.items()
                },
                "planned_directory": str(planned_dir),
            }
            metadata.update(self.dry_run_notice(planned_steps))

            findings = [
                {
                    "type": "dry_run",
                    "description": "Dry-run only planned persistence inspection.",
                    "categories": sorted(path_map.keys()),
                }
            ]

            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="success",
                timestamp=timestamp,
                findings=findings,
                metadata=metadata,
                errors=[],
            )

        records: List[Dict[str, Any]] = []
        warnings: List[str] = []
        summary: Dict[str, Dict[str, Any]] = {}

        for category, paths in path_map.items():
            category_info = CATEGORIES.get(category)
            category_description = (
                category_info.description if category_info else category.title()
            )
            total_paths = len(paths)
            existing_paths = 0
            enumerated_items = 0

            for source_path in paths:
                base_path = Path(source_path).expanduser().resolve()
                exists = base_path.exists()
                readable = exists and os.access(base_path, os.R_OK)
                note: Optional[str] = None

                if exists:
                    existing_paths += 1

                base_record = self._build_record(
                    category=category,
                    source=str(base_path),
                    path=str(base_path),
                    name=base_path.name or str(base_path),
                    item_type=self._determine_type(base_path) if exists else "missing",
                    exists=exists,
                    readable=readable,
                    size_bytes=self._safe_size(base_path) if exists else None,
                    modified=self._safe_mtime(base_path) if exists else None,
                    note=note,
                )
                records.append(base_record)

                if not exists:
                    warnings.append(f"Path not found: {base_path}")
                    continue

                if not readable:
                    warnings.append(
                        f"Path not readable: {base_path} (insufficient permissions)"
                    )
                    continue

                if base_path.is_dir():
                    try:
                        entries = sorted(base_path.iterdir(), key=lambda item: item.name)
                    except PermissionError:
                        warnings.append(
                            f"Unable to enumerate directory contents: {base_path}"
                        )
                        continue

                    for entry in entries:
                        entry_path = entry
                        entry_record = self._build_record(
                            category=category,
                            source=str(base_path),
                            path=str(entry_path),
                            name=entry_path.name,
                            item_type=self._determine_type(entry_path),
                            exists=entry_path.exists() or entry_path.is_symlink(),
                            readable=os.access(entry_path, os.R_OK),
                            size_bytes=self._safe_size(entry_path),
                            modified=self._safe_mtime(entry_path),
                            note=None,
                        )
                        records.append(entry_record)
                        enumerated_items += 1
                else:
                    enumerated_items += 1

            summary[category] = {
                "description": category_description,
                "configured_paths": total_paths,
                "existing_paths": existing_paths,
                "enumerated_items": enumerated_items,
            }

        sorted_records = sorted(
            records, key=lambda item: (item["category"], item["path"], item["name"])
        )

        planned_dir.mkdir(parents=True, exist_ok=True)
        json_path = planned_dir / "persistence.json"
        csv_path = planned_dir / "persistence.csv"

        io.write_json(
            json_path,
            {
                "module": self.name,
                "generated_at": timestamp,
                "timezone": self.timezone,
                "records": sorted_records,
                "summary": summary,
                "warnings": sorted(set(warnings)),
            },
        )

        self._write_csv(csv_path, sorted_records)

        findings = [
            {
                "type": "persistence_summary",
                "category": category,
                "description": f"Enumerated {data['enumerated_items']} entries",
                "configured_paths": data["configured_paths"],
                "existing_paths": data["existing_paths"],
            }
            for category, data in sorted(summary.items())
        ]

        findings.append(
            {
                "type": "persistence_artifacts",
                "description": "Persistence enumeration artifacts generated.",
                "artifacts": [str(json_path), str(csv_path)],
            }
        )

        metadata = {
            "summary": summary,
            "warnings": sorted(set(warnings)),
            "artifacts": [str(json_path), str(csv_path)],
            "paths": {
                category: [str(path) for path in paths]
                for category, paths in path_map.items()
            },
        }

        status = "success"

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=json_path,
            findings=findings,
            metadata=metadata,
            errors=[],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _configurable_categories(self) -> Iterable[str]:
        return sorted(set(DEFAULT_PATHS.keys()) | set(CATEGORIES.keys()))

    def _plan_steps(self, path_map: Mapping[str, Sequence[str]]) -> List[str]:
        steps: List[str] = []
        for category in sorted(path_map.keys()):
            descriptor = CATEGORIES.get(category)
            label = descriptor.description if descriptor else category.title()
            for path in path_map[category]:
                steps.append(f"Enumerate {label} at {path}")
        return steps

    def _planned_directory(self, timestamp: str) -> Path:
        slug = re.sub(r"[^0-9A-Za-z]+", "_", timestamp).strip("_")
        if not slug:
            from ...core.time_utils import utc_slug  # Local import to avoid cycles.

            slug = utc_slug()
        return self.case_dir / "triage" / self.name / slug

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

    def _normalise_path_map(self, raw: Any) -> Dict[str, Tuple[str, ...]]:
        if raw is None:
            return {}

        result: Dict[str, Tuple[str, ...]] = {}

        if isinstance(raw, Mapping):
            for category, value in raw.items():
                normalised_category = str(category).strip().lower()
                if not normalised_category:
                    continue
                entries = self._normalise_path_list(value)
                if entries:
                    result[normalised_category] = entries
        elif isinstance(raw, list | tuple | set):
            entries = self._normalise_path_list(raw)
            if entries:
                result["custom"] = entries
        elif isinstance(raw, str):
            entries = self._normalise_path_list([raw])
            if entries:
                result["custom"] = entries

        if not result:
            for category in self._configurable_categories():
                defaults = DEFAULT_PATHS.get(category)
                if defaults:
                    result[category] = defaults

        return {
            category: tuple(dict.fromkeys(paths))
            for category, paths in sorted(result.items())
        }

    def _normalise_path_list(self, raw: Any) -> Tuple[str, ...]:
        items: Iterable[Any]
        if isinstance(raw, str):
            items = [segment.strip() for segment in raw.split(",")]
        elif isinstance(raw, Iterable):
            items = raw
        else:
            return tuple()

        resolved: List[str] = []
        for item in items:
            if item is None:
                continue
            value = str(item).strip()
            if not value:
                continue
            resolved.append(value)
        return tuple(dict.fromkeys(resolved))

    def _determine_type(self, path: Path) -> str:
        if path.is_symlink():
            return "symlink"
        if path.is_dir():
            return "directory"
        if path.is_file():
            return "file"
        return "other"

    def _safe_size(self, path: Path) -> Optional[int]:
        try:
            return path.stat().st_size
        except OSError:
            return None

    def _safe_mtime(self, path: Path) -> Optional[str]:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None

        dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        if ZoneInfo is not None:
            try:
                dt = dt.astimezone(ZoneInfo(self.timezone))
            except Exception:  # pragma: no cover - timezone fallback
                dt = dt.astimezone(timezone.utc)
        else:  # pragma: no cover - fallback when zoneinfo unavailable
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat()

    def _build_record(
        self,
        *,
        category: str,
        source: str,
        path: str,
        name: str,
        item_type: str,
        exists: bool,
        readable: bool,
        size_bytes: Optional[int],
        modified: Optional[str],
        note: Optional[str],
    ) -> Dict[str, Any]:
        return {
            "category": category,
            "source": source,
            "path": path,
            "name": name,
            "type": item_type,
            "exists": bool(exists),
            "readable": bool(readable),
            "size_bytes": size_bytes,
            "modified": modified,
            "note": note,
        }

    def _write_csv(self, path: Path, records: Sequence[Dict[str, Any]]) -> None:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_HEADERS)
            writer.writeheader()
            for record in records:
                row = {key: record.get(key) for key in CSV_HEADERS}
                writer.writerow(row)


__all__ = ["PersistenceModule"]
