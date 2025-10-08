#!/usr/bin/env python3
"""
Timeline Generation Module
Forensic timeline creation using plaso/log2timeline and mactime

Features:
- plaso (log2timeline) integration for comprehensive timelines
- Sleuthkit mactime support for filesystem timelines
- Multi-source timeline correlation
- Filtering by date range, file types, user activity
- Multiple output formats (CSV, L2TCSV, body, JSON)
- Timeline visualization support
- Unified timeline writer aggregating network analysis output
"""

import csv
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ...core.evidence import Evidence
from ...core.module import AnalysisModule, ModuleResult
from ...core.time_utils import utc_isoformat, utc_slug


class TimelineModule(AnalysisModule):
    """
    Timeline generation module

    Creates forensic timelines from:
    - Disk images
    - Mounted filesystems
    - Log directories
    - Memory dumps (limited support)
    - Network captures (limited support)
    """

    @property
    def name(self) -> str:
        return "timeline"

    @property
    def description(self) -> str:
        return "Generate forensic timeline from evidence"

    @property
    def requires_root(self) -> bool:
        return False

    def validate_params(self, params: Dict) -> bool:
        """Validate parameters"""
        if "source" not in params:
            self.logger.error("Missing required parameter: source")
            return False

        source = Path(params["source"])
        if not source.exists():
            self.logger.error(f"Source does not exist: {source}")
            return False

        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        """Execute timeline generation"""
        result_id = self._generate_result_id()
        timestamp = utc_isoformat()
        timeline_slug = utc_slug()

        source = Path(params["source"])
        output_format = params.get("format", "csv").lower()
        timeline_type = params.get("type", "auto").lower()  # auto, plaso, mactime

        # Date filtering
        start_date = params.get("start_date")
        end_date = params.get("end_date")

        # Advanced options
        include_mft = params.get("include_mft", "true").lower() == "true"
        include_usnjrnl = params.get("include_usnjrnl", "false").lower() == "true"
        include_browser = params.get("include_browser", "true").lower() == "true"
        include_logs = params.get("include_logs", "true").lower() == "true"

        findings = []
        errors = []
        metadata = {
            "source": str(source),
            "timeline_type": timeline_type,
            "output_format": output_format,
            "start": timestamp,
        }

        self.logger.info(f"Generating timeline from: {source}")

        # Auto-detect source type
        if timeline_type == "auto":
            timeline_type = self._detect_timeline_type(source)
            self.logger.info(f"Auto-detected timeline type: {timeline_type}")
        metadata["timeline_type"] = timeline_type

        requirements = {
            "plaso": ["log2timeline.py"],
            "mactime": ["fls", "mactime"],
        }
        required_tools = requirements.get(timeline_type, [])
        missing_tools = [tool for tool in required_tools if not self._verify_tool(tool)]
        if missing_tools:
            guidance = "Install the required timeline tooling to enable this mode."
            return self._missing_tool_result(
                result_id,
                missing_tools,
                metadata=metadata,
                guidance=guidance,
                timestamp=timestamp,
            )

        # Generate timeline
        timeline_file: Optional[Path] = None
        stats: Dict[str, Any] = {}

        try:
            if timeline_type == "plaso":
                timeline_file, stats = self._generate_plaso_timeline(
                    source,
                    output_format,
                    start_date,
                    end_date,
                    include_mft,
                    include_usnjrnl,
                    include_browser,
                    include_logs,
                )
            elif timeline_type == "mactime":
                timeline_file, stats = self._generate_mactime_timeline(
                    source, output_format, start_date, end_date
                )
            elif timeline_type == "simple":
                timeline_file, stats = self._generate_simple_timeline(
                    source, output_format
                )
            else:
                errors.append(f"Unknown timeline type: {timeline_type}")
                return ModuleResult(
                    result_id=result_id,
                    module_name=self.name,
                    status="failed",
                    timestamp=timestamp,
                    findings=findings,
                    metadata=metadata,
                    errors=errors,
                )

            metadata.update(stats)

            findings.append(
                {
                    "type": "timeline_generated",
                    "description": f'Timeline created with {stats.get("total_events", 0)} events',
                    "timeline_type": timeline_type,
                    "output_file": str(timeline_file),
                }
            )

            # Generate summary
            if timeline_file.exists():
                summary = self._analyze_timeline(timeline_file, output_format)
                findings.append(
                    {
                        "type": "timeline_summary",
                        "description": "Timeline analysis summary",
                        **summary,
                    }
                )

        except Exception as e:
            self.logger.error(f"Timeline generation failed: {e}")
            errors.append(f"Timeline generation failed: {e}")
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=findings,
                metadata=metadata,
                errors=errors,
            )

        timeline_events = self._load_timeline_events_from_file(
            timeline_file, timeline_type
        )
        network_events = self._collect_network_events()
        all_events = self._sort_events(timeline_events + network_events)

        timeline_dir = self.case_dir / "timeline" / timeline_slug
        timeline_dir.mkdir(parents=True, exist_ok=True)
        events_csv, events_json = self._write_unified_timeline(all_events, timeline_dir)

        findings.append(
            {
                "type": "unified_timeline",
                "description": "Unified timeline written to case timeline directory",
                "event_count": len(all_events),
                "timeline_directory": str(timeline_dir),
                "csv_file": str(events_csv),
                "json_file": str(events_json),
            }
        )

        metadata.update(
            {
                "timeline_slug": timeline_slug,
                "unified_timeline": {
                    "timeline_dir": str(timeline_dir),
                    "csv_file": str(events_csv),
                    "json_file": str(events_json),
                    "event_count": len(all_events),
                },
                "timeline_events_imported": len(timeline_events),
                "network_event_count": len(network_events),
            }
        )

        metadata["end"] = utc_isoformat()

        status = "success" if not errors else "partial"

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=events_csv,
            findings=findings,
            metadata=metadata,
            errors=errors,
        )

    def _detect_timeline_type(self, source: Path) -> str:
        """Auto-detect appropriate timeline type"""
        # Check for plaso availability
        if self._verify_tool("log2timeline.py"):
            return "plaso"

        # Check for Sleuthkit
        if self._verify_tool("fls") and self._verify_tool("mactime"):
            return "mactime"

        # Fallback to simple
        return "simple"

    def _generate_plaso_timeline(
        self,
        source: Path,
        output_format: str,
        start_date: Optional[str],
        end_date: Optional[str],
        include_mft: bool,
        include_usnjrnl: bool,
        include_browser: bool,
        include_logs: bool,
    ) -> Tuple[Path, Dict]:
        """Generate timeline using plaso/log2timeline"""
        self.logger.info("Using plaso/log2timeline for timeline generation")

        if not self._verify_tool("log2timeline.py"):
            raise RuntimeError("plaso/log2timeline not installed")

        stats = {}

        # Create plaso storage file
        plaso_file = self.output_dir / "timeline.plaso"

        # Build log2timeline command
        cmd = [
            "log2timeline.py",
            "--status_view",
            "none",  # Suppress progress
            "--storage-file",
            str(plaso_file),
        ]

        # Parser selection
        parsers = []
        if include_mft:
            parsers.append("mft")
        if include_usnjrnl:
            parsers.append("usnjrnl")
        if include_browser:
            parsers.extend(["chrome_history", "firefox_history", "safari_history"])
        if include_logs:
            parsers.extend(["syslog", "apache_access", "wevt"])

        if parsers:
            cmd.extend(["--parsers", ",".join(parsers)])

        # Add source
        cmd.append(str(source))

        # Execute log2timeline
        self.logger.info(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3600  # 1 hour timeout
            )

            if result.returncode != 0:
                self.logger.warning(f"log2timeline warning: {result.stderr}")

            stats["log2timeline_rc"] = result.returncode
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("log2timeline timeout") from exc
        except Exception as e:
            raise RuntimeError(f"log2timeline failed: {e}") from e

        # Convert to desired format using psort
        if output_format == "l2tcsv":
            output_file = self.output_dir / "timeline.l2tcsv"
            output_arg = "l2tcsv"
        elif output_format == "json":
            output_file = self.output_dir / "timeline.jsonl"
            output_arg = "json_line"
        else:  # csv
            output_file = self.output_dir / "timeline.csv"
            output_arg = "dynamic"

        psort_cmd = [
            "psort.py",
            "--output_time_zone",
            "UTC",
            "-o",
            output_arg,
            "-w",
            str(output_file),
        ]

        # Date filtering
        if start_date:
            psort_cmd.extend(
                ["--date_filter", f'{start_date}..{end_date or "9999-12-31"}']
            )

        psort_cmd.append(str(plaso_file))

        self.logger.info(f"Running: {' '.join(psort_cmd)}")

        try:
            result = subprocess.run(
                psort_cmd, capture_output=True, text=True, timeout=1800
            )

            if result.returncode != 0:
                self.logger.warning(f"psort warning: {result.stderr}")

            stats["psort_rc"] = result.returncode
        except Exception as e:
            raise RuntimeError(f"psort failed: {e}") from e

        # Count events
        if output_file.exists():
            stats["total_events"] = (
                sum(1 for _ in open(output_file)) - 1
            )  # Minus header

        return output_file, stats

    def _generate_mactime_timeline(
        self,
        source: Path,
        output_format: str,
        start_date: Optional[str],
        end_date: Optional[str],
    ) -> Tuple[Path, Dict]:
        """Generate timeline using Sleuthkit mactime"""
        self.logger.info("Using Sleuthkit mactime for timeline generation")

        if not self._verify_tool("fls"):
            raise RuntimeError("Sleuthkit not installed")

        stats = {}

        # Generate body file
        body_file = self.output_dir / "bodyfile.txt"

        cmd = ["fls", "-r", "-m", "/", str(source)]  # Recursive  # Mount point

        self.logger.info(f"Running: {' '.join(cmd)}")

        try:
            with open(body_file, "w") as f:
                result = subprocess.run(
                    cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=1800
                )

            if result.returncode != 0:
                self.logger.warning(f"fls warning: {result.stderr}")

            stats["fls_rc"] = result.returncode
        except Exception as e:
            raise RuntimeError(f"fls failed: {e}") from e

        # Generate timeline from body file
        timeline_file = self.output_dir / "timeline.csv"

        mactime_cmd = ["mactime", "-b", str(body_file), "-d"]  # CSV output

        # Date filtering
        if start_date:
            mactime_cmd.extend(["-z", "UTC"])
            # mactime uses different date format
            # Convert YYYY-MM-DD to MM/DD/YYYY
            if start_date:
                start_parts = start_date.split("-")
                if len(start_parts) == 3:
                    mactime_cmd.extend(
                        ["-s", f"{start_parts[1]}/{start_parts[2]}/{start_parts[0]}"]
                    )
            if end_date:
                end_parts = end_date.split("-")
                if len(end_parts) == 3:
                    mactime_cmd.extend(
                        ["-e", f"{end_parts[1]}/{end_parts[2]}/{end_parts[0]}"]
                    )

        self.logger.info(f"Running: {' '.join(mactime_cmd)}")

        try:
            with open(timeline_file, "w") as f:
                result = subprocess.run(
                    mactime_cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=600,
                )

            if result.returncode != 0:
                self.logger.warning(f"mactime warning: {result.stderr}")

            stats["mactime_rc"] = result.returncode
        except Exception as e:
            raise RuntimeError(f"mactime failed: {e}") from e

        # Count events
        if timeline_file.exists():
            stats["total_events"] = sum(1 for _ in open(timeline_file))

        return timeline_file, stats

    def _generate_simple_timeline(
        self, source: Path, output_format: str
    ) -> Tuple[Path, Dict]:
        """Generate simple timeline using find + stat"""
        self.logger.info("Using simple timeline generation (find + stat)")

        stats = {}
        timeline_file = self.output_dir / "timeline.csv"

        events = []

        # Walk directory tree
        for root, _dirs, files in (
            source.walk() if source.is_dir() else [(source.parent, [], [source.name])]
        ):
            for fname in files:
                fpath = Path(root) / fname

                try:
                    stat = fpath.stat()

                    # Add events for each timestamp
                    events.append(
                        {
                            "timestamp": datetime.fromtimestamp(
                                stat.st_mtime
                            ).isoformat()
                            + "Z",
                            "type": "MACB",
                            "path": str(fpath),
                            "size": stat.st_size,
                            "description": "File modified",
                        }
                    )

                    events.append(
                        {
                            "timestamp": datetime.fromtimestamp(
                                stat.st_atime
                            ).isoformat()
                            + "Z",
                            "type": "MACB",
                            "path": str(fpath),
                            "size": stat.st_size,
                            "description": "File accessed",
                        }
                    )

                    events.append(
                        {
                            "timestamp": datetime.fromtimestamp(
                                stat.st_ctime
                            ).isoformat()
                            + "Z",
                            "type": "MACB",
                            "path": str(fpath),
                            "size": stat.st_size,
                            "description": "File changed (metadata)",
                        }
                    )
                except Exception:
                    continue

        # Sort by timestamp
        events.sort(key=lambda e: e["timestamp"])

        # Write to CSV
        with open(timeline_file, "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["timestamp", "type", "path", "size", "description"]
            )
            writer.writeheader()
            writer.writerows(events)

        stats["total_events"] = len(events)

        return timeline_file, stats

    def _analyze_timeline(self, timeline_file: Path, output_format: str) -> Dict:
        """Analyze timeline for summary statistics"""
        summary = {}

        try:
            with open(timeline_file, encoding="utf-8") as f:
                lines = list(f)

            summary["total_events"] = len(lines) - 1  # Minus header

            # Date range
            if output_format == "csv" and len(lines) > 2:
                # Assume first column is timestamp
                first_line = lines[1].split(",")[0]
                last_line = lines[-1].split(",")[0]

                summary["date_range_start"] = first_line.strip('"')
                summary["date_range_end"] = last_line.strip('"')

            # File size
            summary["timeline_size_bytes"] = timeline_file.stat().st_size

        except Exception as e:
            self.logger.warning(f"Timeline analysis failed: {e}")

        return summary

    # ------------------------------------------------------------------
    # Unified timeline helpers
    # ------------------------------------------------------------------
    def _load_timeline_events_from_file(
        self, timeline_file: Optional[Path], timeline_type: str
    ) -> List[Dict[str, str]]:
        if not timeline_file or not timeline_file.exists():
            return []

        source_label = f"timeline:{timeline_type}"
        suffix = timeline_file.suffix.lower()

        if suffix in {".json", ".jsonl"}:
            return self._parse_json_timeline(timeline_file, source_label)

        return self._parse_csv_timeline(timeline_file, source_label)

    def _parse_csv_timeline(
        self, timeline_file: Path, source_label: str
    ) -> List[Dict[str, str]]:
        events: List[Dict[str, str]] = []
        timestamp_fields = [
            "timestamp",
            "datetime",
            "datetime_utc",
            "date",
            "time",
        ]
        type_fields = ["type", "event_type", "category", "source"]
        summary_fields = [
            "summary",
            "message",
            "description",
            "event_description",
            "filename",
            "path",
        ]

        try:
            with timeline_file.open(encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                if not reader.fieldnames:
                    return events

                for idx, row in enumerate(reader, start=1):
                    ts_value = self._first_non_empty(row, timestamp_fields)
                    if not ts_value:
                        continue

                    timestamp = self._normalise_timestamp(ts_value)
                    if not timestamp:
                        continue

                    event_type = self._first_non_empty(row, type_fields) or "event"
                    summary = self._first_non_empty(row, summary_fields)
                    if not summary:
                        summary = self._fallback_summary(
                            row, timestamp_fields + type_fields
                        )

                    events.append(
                        {
                            "timestamp": timestamp,
                            "source": source_label,
                            "type": str(event_type),
                            "summary": summary,
                            "details_ref": f"{timeline_file}:{idx + 1}",
                        }
                    )
        except Exception as exc:
            self.logger.debug(
                "Failed to parse CSV timeline %s: %s", timeline_file, exc
            )

        return events

    def _parse_json_timeline(
        self, timeline_file: Path, source_label: str
    ) -> List[Dict[str, str]]:
        events: List[Dict[str, str]] = []
        try:
            if timeline_file.suffix.lower() == ".jsonl":
                with timeline_file.open(encoding="utf-8") as handle:
                    records: Iterable[Any] = (
                        json.loads(line)
                        for line in handle
                        if line.strip()
                    )
                    events.extend(
                        self._events_from_records(
                            records, source_label, timeline_file
                        )
                    )
            else:
                with timeline_file.open(encoding="utf-8") as handle:
                    data = json.load(handle)
                if isinstance(data, list):
                    records = data
                else:
                    records = data.get("events", []) if isinstance(data, dict) else []
                events.extend(
                    self._events_from_records(records, source_label, timeline_file)
                )
        except Exception as exc:
            self.logger.debug(
                "Failed to parse JSON timeline %s: %s", timeline_file, exc
            )

        return events

    def _events_from_records(
        self,
        records: Iterable[Any],
        source_label: str,
        timeline_file: Path,
    ) -> List[Dict[str, str]]:
        events: List[Dict[str, str]] = []
        timestamp_fields = ["timestamp", "datetime", "time", "date"]
        type_fields = ["type", "event_type", "category", "source"]
        summary_fields = [
            "summary",
            "message",
            "description",
            "event_description",
        ]

        for idx, record in enumerate(records, start=1):
            if not isinstance(record, dict):
                continue

            ts_value = self._first_non_empty(record, timestamp_fields)
            if not ts_value:
                continue

            timestamp = self._normalise_timestamp(ts_value)
            if not timestamp:
                continue

            event_type = self._first_non_empty(record, type_fields) or "event"
            summary = self._first_non_empty(record, summary_fields)
            if not summary:
                summary = self._fallback_summary(
                    record, timestamp_fields + type_fields
                )

            events.append(
                {
                    "timestamp": timestamp,
                    "source": source_label,
                    "type": str(event_type),
                    "summary": summary,
                    "details_ref": f"{timeline_file}:{idx}",
                }
            )

        return events

    def _collect_network_events(self) -> List[Dict[str, str]]:
        events: List[Dict[str, str]] = []
        network_root = self.case_dir / "analysis" / "network"
        if not network_root.exists():
            return events

        for network_file in sorted(network_root.glob("**/network.json")):
            try:
                with network_file.open(encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception as exc:
                self.logger.debug(
                    "Failed to load network analysis output %s: %s",
                    network_file,
                    exc,
                )
                continue

            events.extend(self._network_flow_events(payload.get("flows", []), network_file))
            dns_payload = {}
            if isinstance(payload.get("dns"), dict):
                dns_payload = payload.get("dns", {})
            events.extend(
                self._network_dns_events(
                    dns_payload.get("queries", []), network_file
                )
            )
            http_payload = {}
            if isinstance(payload.get("http"), dict):
                http_payload = payload.get("http", {})
            events.extend(
                self._network_http_events(
                    http_payload.get("requests", []), network_file
                )
            )

        return events

    def _network_flow_events(
        self, flows: Iterable[Dict[str, Any]], network_file: Path
    ) -> List[Dict[str, str]]:
        events: List[Dict[str, str]] = []
        for flow in flows:
            if not isinstance(flow, dict):
                continue
            summary = self._flow_summary(flow)
            start_ts = self._normalise_timestamp(flow.get("start_ts"))
            end_ts = self._normalise_timestamp(flow.get("end_ts"))
            details_ref = str(network_file)

            if start_ts:
                events.append(
                    {
                        "timestamp": start_ts,
                        "source": "network",
                        "type": "flow_start",
                        "summary": f"Flow started {summary}",
                        "details_ref": details_ref,
                    }
                )
            if end_ts:
                events.append(
                    {
                        "timestamp": end_ts,
                        "source": "network",
                        "type": "flow_end",
                        "summary": f"Flow ended {summary}",
                        "details_ref": details_ref,
                    }
                )

        return events

    def _network_dns_events(
        self, queries: Iterable[Dict[str, Any]], network_file: Path
    ) -> List[Dict[str, str]]:
        events: List[Dict[str, str]] = []
        for query in queries:
            if not isinstance(query, dict):
                continue
            timestamp = self._normalise_timestamp(query.get("timestamp"))
            if not timestamp:
                continue

            domain = query.get("query") or "(unknown domain)"
            src = query.get("src") or "unknown"
            summary = f"DNS query for {domain} from {src}"
            events.append(
                {
                    "timestamp": timestamp,
                    "source": "network",
                    "type": "dns_query",
                    "summary": summary,
                    "details_ref": str(network_file),
                }
            )

        return events

    def _network_http_events(
        self, requests: Iterable[Dict[str, Any]], network_file: Path
    ) -> List[Dict[str, str]]:
        events: List[Dict[str, str]] = []
        for request in requests:
            if not isinstance(request, dict):
                continue
            timestamp = self._normalise_timestamp(request.get("timestamp"))
            if not timestamp:
                continue

            method = (request.get("method") or "HTTP").upper()
            host = request.get("host") or ""
            uri = request.get("uri") or ""
            if host and uri:
                target = f"{host}{uri}"
            else:
                target = host or uri or "(unknown endpoint)"
            summary = f"HTTP {method} request to {target}"

            events.append(
                {
                    "timestamp": timestamp,
                    "source": "network",
                    "type": "http_request",
                    "summary": summary,
                    "details_ref": str(network_file),
                }
            )

        return events

    def _write_unified_timeline(
        self, events: List[Dict[str, str]], timeline_dir: Path
    ) -> Tuple[Path, Path]:
        csv_path = timeline_dir / "events.csv"
        json_path = timeline_dir / "events.json"

        fieldnames = ["timestamp", "source", "type", "summary", "details_ref"]

        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for event in events:
                writer.writerow({field: event.get(field, "") for field in fieldnames})

        with json_path.open("w", encoding="utf-8") as handle:
            json.dump(events, handle, indent=2, ensure_ascii=False)

        return csv_path, json_path

    def _first_non_empty(
        self, data: Dict[str, Any], candidates: Iterable[str]
    ) -> Optional[str]:
        for key in candidates:
            value = data.get(key)
            if value is None:
                continue
            if isinstance(value, str):
                if value.strip():
                    return value
            else:
                return str(value)
        return None

    def _fallback_summary(
        self, data: Dict[str, Any], exclude_keys: Iterable[str]
    ) -> str:
        exclude = set(exclude_keys)
        parts = []
        for key, value in data.items():
            if key in exclude:
                continue
            if value is None:
                continue
            value_str = str(value).strip()
            if not value_str:
                continue
            parts.append(f"{key}={value_str}")
            if len(parts) >= 3:
                break
        return "; ".join(parts) if parts else "Timeline event"

    def _flow_summary(self, flow: Dict[str, Any]) -> str:
        src = flow.get("src") or "unknown"
        src_port = flow.get("src_port")
        dst = flow.get("dst") or "unknown"
        dst_port = flow.get("dst_port")
        protocol = flow.get("protocol") or "?"
        src_repr = f"{src}:{src_port}" if src_port else str(src)
        dst_repr = f"{dst}:{dst_port}" if dst_port else str(dst)
        return f"{src_repr} -> {dst_repr} ({protocol})"

    def _normalise_timestamp(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, int | float):
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
            except Exception:
                return None

        value_str = str(value).strip()
        if not value_str or value_str.lower() == "unknown":
            return None

        iso_candidate = value_str
        if iso_candidate.endswith("Z"):
            iso_candidate = iso_candidate[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(iso_candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass

        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(value_str, fmt)
                dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except ValueError:
                continue

        try:
            return datetime.fromtimestamp(float(value_str), tz=timezone.utc).isoformat()
        except Exception:
            return None

    def _sort_events(self, events: List[Dict[str, str]]) -> List[Dict[str, str]]:
        def sort_key(event: Dict[str, str]) -> Tuple:
            timestamp = event.get("timestamp")
            dt: datetime
            if timestamp:
                ts = timestamp
                if ts.endswith("Z"):
                    ts = ts[:-1] + "+00:00"
                try:
                    dt = datetime.fromisoformat(ts)
                except ValueError:
                    dt = datetime.min.replace(tzinfo=timezone.utc)
            else:
                dt = datetime.min.replace(tzinfo=timezone.utc)

            return (
                dt,
                event.get("source", ""),
                event.get("type", ""),
                event.get("summary", ""),
            )

        return sorted(events, key=sort_key)
