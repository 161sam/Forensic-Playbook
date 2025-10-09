"""Guarded quick triage module with deterministic exports."""

from __future__ import annotations

import csv
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:  # Python 3.9+
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback when tzdata missing
    ZoneInfo = None  # type: ignore

from ...core.evidence import Evidence
from ...core.module import ModuleResult, TriageModule
from ...utils import io

CSV_HEADERS: Tuple[str, ...] = ("check", "path", "reason", "details")


@dataclass(frozen=True)
class SuidSgidConfig:
    """Configuration for SUID/SGID scanning."""

    enabled: bool = True
    suspicious_globs: Tuple[str, ...] = ()
    max_results: Optional[int] = None


@dataclass(frozen=True)
class RecentFilesConfig:
    """Configuration for recent file discovery."""

    enabled: bool = True
    since_days: Optional[int] = None
    include_globs: Tuple[str, ...] = ("**",)
    exclude_globs: Tuple[str, ...] = ()
    max_results: Optional[int] = None


@dataclass(frozen=True)
class SuspiciousPathsConfig:
    """Configuration for suspicious path matching."""

    enabled: bool = True
    glob_patterns: Tuple[str, ...] = ()
    max_results: Optional[int] = None


class QuickTriageModule(TriageModule):
    """Summarise common triage indicators with guard rails."""

    @property
    def name(self) -> str:
        return "quick_triage"

    @property
    def description(self) -> str:
        return "Quick system triage for privileged binaries and artefacts"

    def _config_defaults(self) -> Dict[str, Any]:
        return self._module_config("triage", "quick_triage")

    def validate_params(self, params: Dict) -> bool:
        defaults = self._config_defaults()

        target_value = params.get("target") or defaults.get("target")
        if not target_value:
            self.logger.error("Missing required parameter: target")
            return False

        target_path = Path(str(target_value)).expanduser()
        if not target_path.exists():
            self.logger.error("Target path does not exist: %s", target_path)
            return False
        if not target_path.is_dir():
            self.logger.error("Target path must be a directory: %s", target_path)
            return False

        params["target"] = target_path

        dry_run = self._to_bool(params.get("dry_run", defaults.get("dry_run", False)))
        params["dry_run"] = dry_run

        max_results = self._normalise_positive_int(
            params.get("max_results", defaults.get("max_results"))
        )
        if max_results is not None and max_results <= 0:
            self.logger.error("max_results must be a positive integer when provided.")
            return False
        params["max_results"] = max_results

        since_value = params.get("since", defaults.get("since"))
        if since_value is None:
            since_value = defaults.get("since_days", defaults.get("recent_days", 7))
        params["since"] = since_value

        exports = defaults.get("exports", {})
        params.setdefault("exports", exports)

        checks_config = defaults.get("checks", {})
        params.setdefault("checks", checks_config)

        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        del evidence  # Offline triage operates on a mounted filesystem snapshot.

        result_id = self._generate_result_id()
        timestamp = self.current_timestamp()
        defaults = self._config_defaults()

        target_param = params.get("target")
        if not target_param:
            return self.guard_result(
                "No target directory specified for quick triage.",
                hints=["Provide --param target=/path/to/mount"],
                metadata={"target": target_param},
                result_id=result_id,
                timestamp=timestamp,
            )
        target = (
            target_param
            if isinstance(target_param, Path)
            else Path(str(target_param)).expanduser()
        )
        dry_run = self._to_bool(params.get("dry_run", defaults.get("dry_run", False)))
        max_results = self._normalise_positive_int(
            params.get("max_results", defaults.get("max_results"))
        )

        since_input = params.get("since")
        since_dt, since_meta = self._resolve_since(since_input)

        if since_dt is None:
            return self.guard_result(
                "Unable to resolve a valid --since threshold for quick triage.",
                hints=[
                    "Provide --since <days|ISO-8601> or configure triage.quick_triage.since_days.",
                ],
                metadata={"since": since_input},
                result_id=result_id,
                timestamp=timestamp,
            )

        since_meta = dict(since_meta)
        since_meta["threshold"] = since_dt.isoformat()

        checks_config = params.get("checks", defaults.get("checks", {}))

        suid_config = self._normalise_suid_config(checks_config.get("suid_sgid"))
        recent_config = self._normalise_recent_config(checks_config.get("recent_files"))
        suspicious_config = self._normalise_suspicious_config(
            checks_config.get("suspicious_paths")
        )

        planned_dir = self._planned_directory(timestamp)
        planned_steps = self._plan_steps(
            target=target,
            suid=suid_config,
            recent=recent_config,
            suspicious=suspicious_config,
            since_meta=since_meta,
            max_results=max_results,
        )

        if dry_run:
            metadata = {
                "target": str(target),
                "since": since_meta,
                "planned_directory": str(planned_dir),
            }
            metadata.update(self.dry_run_notice(planned_steps))

            findings = [
                {
                    "type": "dry_run",
                    "description": "Dry-run only planned quick triage checks.",
                    "checks": [
                        name
                        for name, enabled in (
                            ("suid_sgid", suid_config.enabled),
                            ("recent_files", recent_config.enabled),
                            ("suspicious_paths", suspicious_config.enabled),
                        )
                        if enabled
                    ],
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

        if not target.exists() or not target.is_dir():
            return self.guard_result(
                "Quick triage target directory is not accessible.",
                hints=[f"Verify that {target} exists and is readable."],
                metadata={"target": str(target)},
                result_id=result_id,
                timestamp=timestamp,
            )

        planned_dir.mkdir(parents=True, exist_ok=True)

        outcomes: List[Dict[str, Any]] = []
        csv_records: List[Dict[str, Any]] = []
        errors: List[str] = []

        if suid_config.enabled:
            outcome, records = self._collect_suid_sgid(
                target=target,
                config=suid_config,
                max_results=max_results,
            )
            outcomes.append(outcome)
            csv_records.extend(records)

        if recent_config.enabled:
            outcome, records = self._collect_recent_files(
                target=target,
                config=recent_config,
                since=since_dt,
                max_results=max_results,
            )
            outcomes.append(outcome)
            csv_records.extend(records)

        if suspicious_config.enabled:
            outcome, records = self._collect_suspicious_paths(
                target=target,
                config=suspicious_config,
                max_results=max_results,
            )
            outcomes.append(outcome)
            csv_records.extend(records)

        summary = {
            "module": self.name,
            "generated_at": timestamp,
            "target": str(target),
            "since": since_meta,
            "checks": outcomes,
        }

        json_path = planned_dir / "summary.json"
        io.write_json(json_path, summary)

        csv_path: Optional[Path] = None
        exports = params.get("exports", defaults.get("exports", {}))
        if self._to_bool(exports.get("csv", True)) and csv_records:
            csv_path = planned_dir / "summary.csv"
            self._write_csv(csv_path, csv_records)

        findings = []
        for outcome in outcomes:
            findings.append(
                {
                    "type": outcome.get("name"),
                    "severity": outcome.get("severity", "info"),
                    "description": outcome.get("description"),
                    "total": outcome.get("total", 0),
                    "reported": len(outcome.get("items", [])),
                    "truncated": outcome.get("truncated", False),
                }
            )

        metadata = {
            "target": str(target),
            "since": since_meta,
            "artifacts": [str(json_path)],
        }
        if csv_path:
            metadata["artifacts"].append(str(csv_path))
        if errors:
            metadata["warnings"] = errors

        status = "success" if not errors else "partial"

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=json_path,
            findings=findings,
            metadata=metadata,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Check collection helpers
    # ------------------------------------------------------------------

    def _collect_suid_sgid(
        self,
        *,
        target: Path,
        config: SuidSgidConfig,
        max_results: Optional[int],
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        limit = self._resolve_limit(max_results, config.max_results)
        suspicious_globs = config.suspicious_globs

        matches: List[Dict[str, Any]] = []

        for root, dirs, files in os.walk(target, followlinks=False):
            dirs.sort()
            files.sort()
            for name in files:
                path = Path(root) / name
                try:
                    st = path.lstat()
                except OSError:
                    continue

                if not stat.S_ISREG(st.st_mode):
                    continue

                is_suid = bool(st.st_mode & stat.S_ISUID)
                is_sgid = bool(st.st_mode & stat.S_ISGID)
                if not (is_suid or is_sgid):
                    continue

                owner = self._owner_name(st.st_uid)
                group = self._group_name(st.st_gid)
                rel_path = self._relativise(path, target)
                reason = ",".join(
                    segment
                    for segment, flag in (("suid", is_suid), ("sgid", is_sgid))
                    if flag
                )
                suspicious = any(
                    self._matches_glob(path, pattern, target)
                    for pattern in suspicious_globs
                )

                record = {
                    "path": rel_path,
                    "absolute_path": str(path),
                    "mode": self._format_mode(st.st_mode),
                    "owner": owner,
                    "group": group,
                    "size_bytes": st.st_size,
                    "reason": reason,
                    "suspicious": suspicious,
                }
                matches.append(record)

        matches.sort(key=lambda item: item["path"])

        truncated = bool(limit and len(matches) > limit)
        reported = matches[:limit] if limit else matches

        outcome = {
            "name": "suid_sgid",
            "description": "SUID/SGID binaries located on the target filesystem.",
            "severity": "medium" if matches else "info",
            "total": len(matches),
            "truncated": truncated,
            "items": reported,
            "suspicious_count": sum(1 for item in matches if item["suspicious"]),
        }

        csv_records = [
            {
                "check": "suid_sgid",
                "path": item["path"],
                "reason": item["reason"],
                "details": self._stable_json(
                    {
                        "mode": item["mode"],
                        "owner": item["owner"],
                        "group": item["group"],
                        "size_bytes": item["size_bytes"],
                        "suspicious": item["suspicious"],
                    }
                ),
            }
            for item in reported
        ]

        return outcome, csv_records

    def _collect_recent_files(
        self,
        *,
        target: Path,
        config: RecentFilesConfig,
        since: datetime,
        max_results: Optional[int],
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        limit = self._resolve_limit(max_results, config.max_results)
        include_patterns = config.include_globs or ("**",)
        exclude_patterns = config.exclude_globs

        effective_since = since
        if config.since_days:
            tz = since.tzinfo or timezone.utc
            override = datetime.now(tz=tz) - timedelta(days=config.since_days)
            if override > effective_since:
                effective_since = override

        since_ts = effective_since.timestamp()

        matches: List[Dict[str, Any]] = []

        for root, dirs, files in os.walk(target, followlinks=False):
            dirs.sort()
            files.sort()
            for name in files:
                path = Path(root) / name
                try:
                    st = path.stat()
                except OSError:
                    continue

                if not stat.S_ISREG(st.st_mode):
                    continue

                if st.st_mtime < since_ts:
                    continue

                if not self._glob_included(path, include_patterns, target):
                    continue
                if self._glob_excluded(path, exclude_patterns, target):
                    continue

                rel_path = self._relativise(path, target)
                matches.append(
                    {
                        "path": rel_path,
                        "absolute_path": str(path),
                        "modified": self._format_mtime(st.st_mtime),
                        "size_bytes": st.st_size,
                        "reason": "recent",
                    }
                )

        matches.sort(
            key=lambda item: (-self._parse_epoch(item["modified"]), item["path"])
        )

        truncated = bool(limit and len(matches) > limit)
        reported = matches[:limit] if limit else matches

        outcome = {
            "name": "recent_files",
            "description": "Files modified since the configured threshold.",
            "severity": "info" if matches else "low",
            "total": len(matches),
            "truncated": truncated,
            "items": reported,
            "threshold": effective_since.isoformat(),
        }

        csv_records = [
            {
                "check": "recent_files",
                "path": item["path"],
                "reason": "recent",
                "details": self._stable_json(
                    {
                        "modified": item["modified"],
                        "size_bytes": item["size_bytes"],
                    }
                ),
            }
            for item in reported
        ]

        return outcome, csv_records

    def _collect_suspicious_paths(
        self,
        *,
        target: Path,
        config: SuspiciousPathsConfig,
        max_results: Optional[int],
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        limit = self._resolve_limit(max_results, config.max_results)
        patterns = config.glob_patterns

        matches: List[Dict[str, Any]] = []

        for pattern in patterns:
            resolved = self._expand_pattern(target, pattern)
            if not resolved:
                continue
            for path in resolved:
                try:
                    st = path.lstat()
                except OSError:
                    continue

                rel_path = self._relativise(path, target)
                item_type = self._determine_type(st)
                entry = {
                    "path": rel_path,
                    "absolute_path": str(path),
                    "pattern": pattern,
                    "type": item_type,
                    "mode": self._format_mode(st.st_mode),
                    "modified": self._format_mtime(st.st_mtime),
                    "reason": "pattern_match",
                }
                if stat.S_ISREG(st.st_mode):
                    entry["size_bytes"] = st.st_size
                matches.append(entry)

        matches.sort(key=lambda item: (item["path"], item["pattern"]))

        truncated = bool(limit and len(matches) > limit)
        reported = matches[:limit] if limit else matches

        outcome = {
            "name": "suspicious_paths",
            "description": "Known suspicious path patterns present on disk.",
            "severity": "medium" if matches else "info",
            "total": len(matches),
            "truncated": truncated,
            "items": reported,
        }

        csv_records = [
            {
                "check": "suspicious_paths",
                "path": item["path"],
                "reason": item["reason"],
                "details": self._stable_json(
                    {
                        "pattern": item["pattern"],
                        "type": item["type"],
                        "modified": item.get("modified"),
                    }
                ),
            }
            for item in reported
        ]

        return outcome, csv_records

    # ------------------------------------------------------------------
    # Planning & configuration helpers
    # ------------------------------------------------------------------

    def _plan_steps(
        self,
        *,
        target: Path,
        suid: SuidSgidConfig,
        recent: RecentFilesConfig,
        suspicious: SuspiciousPathsConfig,
        since_meta: Mapping[str, Any],
        max_results: Optional[int],
    ) -> List[str]:
        steps: List[str] = []
        limit_label = str(max_results) if max_results else "inf"
        if suid.enabled:
            steps.append(
                f"Enumerate SUID/SGID binaries under {target} (limit={limit_label})"
            )
        if recent.enabled:
            steps.append(
                "List recently modified files since "
                f"{since_meta.get('threshold') or since_meta.get('resolved', 'threshold')}"
                f" (limit={limit_label})"
            )
        if suspicious.enabled:
            steps.append(
                "Check known suspicious glob patterns"
                f" ({len(suspicious.glob_patterns)} patterns)"
            )
        return steps

    def _planned_directory(self, timestamp: str) -> Path:
        import re

        slug = re.sub(r"[^0-9A-Za-z]+", "_", timestamp).strip("_")
        if not slug:
            from ...core.time_utils import utc_slug  # Local import to avoid cycles.

            slug = utc_slug()
        return self.case_dir / "triage" / self.name / slug

    def _normalise_suid_config(self, raw: Any) -> SuidSgidConfig:
        if not isinstance(raw, Mapping):
            raw = {}
        enabled = self._to_bool(raw.get("enabled", True))
        suspicious_globs = self._normalise_glob_list(raw.get("suspicious_globs"))
        max_results = self._normalise_positive_int(raw.get("max_results"))
        return SuidSgidConfig(
            enabled=enabled,
            suspicious_globs=suspicious_globs,
            max_results=max_results,
        )

    def _normalise_recent_config(self, raw: Any) -> RecentFilesConfig:
        if not isinstance(raw, Mapping):
            raw = {}
        enabled = self._to_bool(raw.get("enabled", True))
        since_days = self._normalise_positive_int(raw.get("since_days"))
        include_globs = self._normalise_glob_list(
            raw.get("include_globs", ("**",))
        ) or ("**",)
        exclude_globs = self._normalise_glob_list(raw.get("exclude_globs"))
        max_results = self._normalise_positive_int(raw.get("max_results"))
        return RecentFilesConfig(
            enabled=enabled,
            since_days=since_days,
            include_globs=include_globs,
            exclude_globs=exclude_globs,
            max_results=max_results,
        )

    def _normalise_suspicious_config(self, raw: Any) -> SuspiciousPathsConfig:
        if not isinstance(raw, Mapping):
            raw = {}
        enabled = self._to_bool(raw.get("enabled", True))
        glob_patterns = self._normalise_glob_list(raw.get("glob_patterns"))
        max_results = self._normalise_positive_int(raw.get("max_results"))
        return SuspiciousPathsConfig(
            enabled=enabled,
            glob_patterns=glob_patterns,
            max_results=max_results,
        )

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    def _resolve_since(self, raw: Any) -> Tuple[Optional[datetime], Dict[str, Any]]:
        tzinfo = timezone.utc
        if ZoneInfo is not None:
            try:
                tzinfo = ZoneInfo(self.timezone)
            except Exception:  # pragma: no cover - fallback when tzdata missing
                tzinfo = timezone.utc

        now = datetime.now(tz=tzinfo)
        meta: Dict[str, Any] = {"input": raw, "timezone": str(tzinfo)}

        if raw is None:
            meta["resolved"] = 7
            meta["source"] = "default"
            return now - timedelta(days=7), meta

        value = raw
        source = "config"

        if isinstance(value, int | float):
            meta["resolved"] = int(value)
            meta["source"] = source
            return now - timedelta(days=float(value)), meta

        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None, meta
            source = "cli"
            if stripped.isdigit():
                days = int(stripped)
                meta["resolved"] = days
                meta["source"] = source
                return now - timedelta(days=days), meta
            try:
                parsed = datetime.fromisoformat(stripped)
            except ValueError:
                return None, meta
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = parsed.astimezone(tzinfo)
            meta["resolved"] = parsed.isoformat()
            meta["source"] = source
            return parsed, meta

        return None, meta

    def _format_mode(self, mode: int) -> str:
        return f"0o{stat.S_IMODE(mode):04o}"

    def _format_mtime(self, epoch: float) -> str:
        tzinfo = timezone.utc
        if ZoneInfo is not None:
            try:
                tzinfo = ZoneInfo(self.timezone)
            except Exception:  # pragma: no cover - fallback when tzdata missing
                tzinfo = timezone.utc
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc).astimezone(tzinfo)
        return dt.isoformat()

    def _parse_epoch(self, iso_ts: str) -> float:
        try:
            dt = datetime.fromisoformat(iso_ts)
        except ValueError:
            return 0.0
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()

    def _owner_name(self, uid: int) -> str:
        try:
            import pwd

            return pwd.getpwuid(uid).pw_name
        except Exception:  # pragma: no cover - fallback on non-POSIX systems
            return str(uid)

    def _group_name(self, gid: int) -> str:
        try:
            import grp

            return grp.getgrgid(gid).gr_name
        except Exception:  # pragma: no cover - fallback on non-POSIX systems
            return str(gid)

    def _determine_type(self, st: os.stat_result) -> str:
        if stat.S_ISDIR(st.st_mode):
            return "directory"
        if stat.S_ISLNK(st.st_mode):
            return "symlink"
        if stat.S_ISREG(st.st_mode):
            return "file"
        return "other"

    def _relativise(self, path: Path, root: Path) -> str:
        try:
            return str(path.relative_to(root)) or "."
        except ValueError:
            return str(path)

    def _matches_glob(self, path: Path, pattern: str, root: Path) -> bool:
        if not pattern:
            return False
        normalised = self._normalise_glob(pattern)
        if not normalised:
            return False
        rel = self._relativise(path, root)
        candidates = self._candidate_paths(rel, path)
        return any(self._pure_match(candidate, normalised) for candidate in candidates)

    def _glob_included(self, path: Path, patterns: Sequence[str], root: Path) -> bool:
        if not patterns:
            return True
        rel = self._relativise(path, root)
        candidates = self._candidate_paths(rel, path)
        for pattern in patterns:
            normalised = self._normalise_glob(pattern)
            if not normalised:
                continue
            if any(self._pure_match(candidate, normalised) for candidate in candidates):
                return True
        return False

    def _glob_excluded(self, path: Path, patterns: Sequence[str], root: Path) -> bool:
        if not patterns:
            return False
        rel = self._relativise(path, root)
        candidates = self._candidate_paths(rel, path)
        for pattern in patterns:
            normalised = self._normalise_glob(pattern)
            if not normalised:
                continue
            if any(self._pure_match(candidate, normalised) for candidate in candidates):
                return True
        return False

    def _expand_pattern(self, root: Path, pattern: str) -> List[Path]:
        normalised = self._normalise_glob(pattern)
        if not normalised:
            return []
        if any(ch in normalised for ch in "*?[]"):
            matches = list((root).glob(normalised))
        else:
            candidate = root / normalised
            matches = [candidate] if candidate.exists() else []
        unique: Dict[str, Path] = {}
        for path in matches:
            unique[str(path)] = path
        return sorted(unique.values(), key=lambda item: str(item))

    def _write_csv(self, path: Path, records: Sequence[Dict[str, Any]]) -> None:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_HEADERS)
            writer.writeheader()
            for record in sorted(
                records, key=lambda item: (item["check"], item["path"])
            ):
                writer.writerow({key: record.get(key, "") for key in CSV_HEADERS})

    def _stable_json(self, data: Mapping[str, Any]) -> str:
        import json

        return json.dumps(dict(data), sort_keys=True, separators=(",", ":"))

    def _normalise_glob_list(self, raw: Any) -> Tuple[str, ...]:
        if raw is None:
            return ()
        items: Iterable[Any]
        if isinstance(raw, str):
            items = [segment.strip() for segment in raw.split(",")]
        elif isinstance(raw, Iterable):
            items = raw
        else:
            return ()
        patterns = [
            self._normalise_glob(str(item)) for item in items if str(item).strip()
        ]
        unique = dict.fromkeys(pattern for pattern in patterns if pattern)
        return tuple(unique.keys())

    def _normalise_glob(self, pattern: str) -> str:
        cleaned = pattern.strip()
        if cleaned.startswith("/"):
            cleaned = cleaned[1:]
        cleaned = cleaned.lstrip("/")
        if cleaned.startswith("./"):
            cleaned = cleaned[2:]
        return cleaned.replace("\\", "/")

    def _normalise_positive_int(self, raw: Any) -> Optional[int]:
        if raw is None:
            return None
        if isinstance(raw, bool):
            return 1 if raw else None
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        if value <= 0:
            return None
        return value

    def _resolve_limit(self, *values: Optional[int]) -> Optional[int]:
        candidates = [value for value in values if isinstance(value, int) and value > 0]
        if not candidates:
            return None
        return min(candidates)

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

    def _candidate_paths(self, relative: str, path: Path) -> Tuple[PurePosixPath, ...]:
        posix_rel = relative.replace("\\", "/")
        if not posix_rel:
            posix_rel = "."
        candidates: List[str] = [posix_rel]
        if posix_rel != f"./{posix_rel}":
            candidates.append(f"./{posix_rel}")

        posix_abs = path.as_posix()
        candidates.extend([posix_abs, posix_abs.lstrip("/")])

        unique: Dict[str, PurePosixPath] = {}
        for candidate in candidates:
            if candidate and candidate not in unique:
                unique[candidate] = PurePosixPath(candidate)

        return tuple(unique.values())

    def _pure_match(self, candidate: PurePosixPath, pattern: str) -> bool:
        if candidate.match(pattern):
            return True
        if not pattern.startswith("**/"):
            return candidate.match(f"**/{pattern}")
        return False


__all__ = ["QuickTriageModule"]
