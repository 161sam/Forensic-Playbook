#!/usr/bin/env python3
"""Reporting module with guarded fallbacks and deterministic exports."""

import json
import sqlite3
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ...core.evidence import Evidence
from ...core.module import ModuleResult, ReportingModule
from ...core.time_utils import utc_isoformat, utc_slug
from .exporter import export_pdf, export_report, get_pdf_renderer


class ReportGenerator(ReportingModule):
    """
    Report generation module

    Generates comprehensive forensic investigation reports
    from case data and analysis results.
    """

    def __init__(self, case_dir: Path, config: Dict):
        super().__init__(case_dir=case_dir, config=config)
        self.defaults = self._module_config("reporting", "reports")
        configured_output_dir = self.defaults.get("output_dir")

        if configured_output_dir:
            candidate_path = Path(configured_output_dir)
            if not candidate_path.is_absolute():
                candidate_path = self.case_dir / configured_output_dir
            self.output_dir = candidate_path
        else:
            self.output_dir = self.case_dir / "reports"

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.template_name = self.defaults.get("template", "report.html")
        self.templates_dir = Path(__file__).with_name("templates")
        self.templates_available = all(
            (self.templates_dir / name).exists()
            for name in {"base.html", self.template_name}
        )

    @property
    def name(self) -> str:
        return "report_generator"

    @property
    def description(self) -> str:
        return "Generate forensic investigation reports"

    @property
    def requires_root(self) -> bool:
        return False

    def validate_params(self, params: Dict) -> bool:
        """Validate parameters"""
        # Case ID will come from framework context
        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        """Generate report"""
        result_id = self._generate_result_id()
        timestamp = utc_isoformat()
        slug = self._timestamp_to_slug(timestamp)

        requested_format = (
            params.get("fmt")
            or params.get("format")
            or self.defaults.get("default_format", "html")
        )
        report_format = (requested_format or "html").lower()
        canonical_format = {"markdown": "md"}.get(report_format, report_format)

        supported_formats = {"html", "md", "json", "pdf"}
        if canonical_format not in supported_formats:
            errors = [
                (
                    "Unsupported report format: "
                    f"{report_format} (supported: html, md, json, pdf)"
                )
            ]
            metadata = {
                "requested_format": report_format,
                "generation_start": timestamp,
                "output_dir": str(self.output_dir),
                "template": self.template_name,
                "templates_available": self.templates_available,
            }
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=[],
                metadata=metadata,
                errors=errors,
            )

        output_file = params.get("output_file")
        dry_run = bool(params.get("dry_run", False))

        # Report sections to include
        include_executive_summary = (
            params.get("executive_summary", "true").lower() == "true"
        )
        include_timeline = params.get("timeline", "true").lower() == "true"
        include_evidence = params.get("evidence", "true").lower() == "true"
        include_findings = params.get("findings", "true").lower() == "true"
        include_coc = params.get("chain_of_custody", "true").lower() == "true"

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        alerts: List[str] = []
        metadata: Dict[str, Any] = {
            "requested_format": canonical_format,
            "generation_start": timestamp,
            "output_dir": str(self.output_dir),
            "template": self.template_name,
            "templates_available": self.templates_available,
            "base_name": f"report_{slug}",
        }

        self.logger.info(f"Generating {report_format.upper()} report...")

        try:
            # Gather report data
            report_data = self._gather_report_data(
                include_executive_summary,
                include_timeline,
                include_evidence,
                include_findings,
                include_coc,
            )

            metadata["sections"] = sorted(report_data.keys())
            metadata["output_format"] = canonical_format

            self._collect_section_alerts(report_data, alerts)
            report_data["alerts"] = alerts

            output_path: Optional[Path] = None
            html_path: Optional[Path] = None
            metadata["alerts"] = alerts

            if dry_run:
                metadata["dry_run"] = True
                planned_path, collision = self._prepare_output_path(
                    output_file, metadata["base_name"], canonical_format
                )
                if collision:
                    metadata["output_path_conflict"] = collision
                if planned_path:
                    metadata["planned_output"] = str(planned_path)
                if canonical_format == "pdf":
                    html_preview, _ = self._prepare_output_path(
                        None, metadata["base_name"], "html"
                    )
                    if html_preview:
                        metadata["planned_html"] = str(html_preview)
                findings.append(
                    {
                        "type": "dry_run",
                        "description": f"Prepared {canonical_format.upper()} report",
                        "output_file": str(planned_path) if planned_path else None,
                    }
                )
                output_path = None
            elif canonical_format == "json":
                target_path, collision = self._prepare_output_path(
                    output_file, metadata["base_name"], "json"
                )
                if collision:
                    errors.append(collision)
                    metadata["output_path_conflict"] = collision
                elif target_path:
                    output_path = export_report(report_data, "json", target_path)
                    metadata["output_path"] = str(output_path)
            elif canonical_format == "md":
                target_path, collision = self._prepare_output_path(
                    output_file, metadata["base_name"], "md"
                )
                if collision:
                    errors.append(collision)
                    metadata["output_path_conflict"] = collision
                elif target_path:
                    output_path = export_report(report_data, "md", target_path)
                    metadata["output_path"] = str(output_path)
            elif canonical_format == "html":
                target_path, collision = self._prepare_output_path(
                    output_file, metadata["base_name"], "html"
                )
                if collision:
                    errors.append(collision)
                    metadata["output_path_conflict"] = collision
                elif target_path:
                    output_path = self._generate_html_report(
                        report_data, target_path, alerts, metadata
                    )
                    html_path = output_path
                    metadata["output_path"] = str(output_path)
            elif canonical_format == "pdf":
                target_path, collision = self._prepare_output_path(
                    output_file, metadata["base_name"], "pdf"
                )
                if collision:
                    errors.append(collision)
                    metadata["output_path_conflict"] = collision
                elif target_path:
                    renderer = get_pdf_renderer()
                    metadata["pdf_renderer"] = renderer
                    if renderer:
                        if output_file:
                            html_candidate = target_path.with_suffix(".html")
                            if html_candidate.exists():
                                html_candidate = self._ensure_unique_path(
                                    html_candidate
                                )
                        else:
                            html_candidate = self._ensure_unique_path(
                                self.output_dir / f"{metadata['base_name']}.html"
                            )
                        html_path = self._generate_html_report(
                            report_data, html_candidate, alerts, metadata
                        )
                        metadata["html_intermediate"] = str(html_path)
                        pdf_result = self._generate_pdf_report(
                            html_path, target_path, alerts, metadata
                        )
                        if pdf_result is None:
                            output_path = html_path
                            metadata["output_format"] = "html"
                            self._append_alert(
                                alerts,
                                "PDF conversion failed; delivered HTML report instead.",
                            )
                            findings.append(
                                {
                                    "type": "pdf_conversion_failed",
                                    "description": (
                                        "PDF conversion failed; delivered HTML report instead."
                                    ),
                                    "output_file": str(html_path),
                                }
                            )
                        else:
                            output_path = pdf_result
                            metadata["output_path"] = str(output_path)
                    else:
                        fallback_target = (
                            target_path.with_suffix(".html") if output_file else None
                        )
                        if fallback_target is not None and fallback_target.exists():
                            fallback_target = self._ensure_unique_path(fallback_target)
                        html_target = (
                            fallback_target
                            if fallback_target is not None
                            else self._ensure_unique_path(
                                self.output_dir / f"{metadata['base_name']}.html"
                            )
                        )
                        self._append_alert(
                            alerts,
                            "PDF renderer not available; generated HTML report instead.",
                        )
                        metadata["output_format"] = "html"
                        metadata["fallback_format"] = "html"
                        html_path = self._generate_html_report(
                            report_data, html_target, alerts, metadata
                        )
                        output_path = html_path
                        metadata["output_path"] = str(output_path)
                        findings.append(
                            {
                                "type": "pdf_renderer_unavailable",
                                "description": (
                                    "PDF renderer not available; generated HTML report instead."
                                ),
                                "output_file": str(output_path),
                            }
                        )

            if output_path and metadata.get("output_path") is None:
                metadata["output_path"] = str(output_path)
            if dry_run:
                metadata.setdefault("output_path", None)
            elif output_path is None and not errors:
                errors.append("Report generation did not produce an output artefact")

            result_format = metadata.get("output_format", canonical_format)

            if not dry_run and output_path is not None:
                findings.append(
                    {
                        "type": "report_generated",
                        "description": f"{result_format.upper()} report generated successfully",
                        "output_file": str(output_path),
                    }
                )

        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            errors.append(f"Report generation failed: {e}")
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=findings,
                metadata=metadata,
                errors=errors,
            )

        metadata["alerts"] = alerts
        metadata["generation_end"] = utc_isoformat()

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status="success" if not errors else "partial",
            timestamp=timestamp,
            output_path=output_path,
            findings=findings,
            metadata=metadata,
            errors=errors,
        )

    def _gather_report_data(
        self,
        include_executive: bool,
        include_timeline: bool,
        include_evidence: bool,
        include_findings: bool,
        include_coc: bool,
    ) -> Dict:
        """Gather all data needed for report"""
        data = {}

        # Case metadata
        data["case"] = self._get_case_metadata()

        # Executive summary
        if include_executive:
            data["executive_summary"] = self._generate_executive_summary()

        # Evidence inventory
        if include_evidence:
            data["evidence"] = self._get_evidence_inventory()

        # Analysis findings
        if include_findings:
            data["findings"] = self._get_all_findings()

        # Timeline
        if include_timeline:
            data["timeline"] = self._get_timeline_data()

        # Network analysis summary
        data["network"] = self._get_network_report_data()

        # Chain of Custody
        if include_coc:
            data["chain_of_custody"] = self._get_coc_events()

        # Statistics
        data["statistics"] = self._calculate_statistics(data)

        return data

    def _locate_workspace_file(self, filename: str) -> Optional[Path]:
        """Search upwards from the case directory for ``filename``."""

        for root in (self.case_dir, *self.case_dir.parents):
            candidate = root / filename
            if candidate.exists():
                return candidate
        return None

    def _get_case_metadata(self) -> Dict:
        """Get case metadata from database"""
        case_db = self._locate_workspace_file("cases.db")

        if case_db is None:
            return {"error": "Case database not found"}

        conn = sqlite3.connect(case_db)
        cursor = conn.cursor()

        # Get case info
        cursor.execute(
            """
            SELECT case_id, name, description, investigator, created_at, metadata
            FROM cases
            WHERE case_dir = ?
        """,
            (str(self.case_dir),),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                "case_id": row[0],
                "name": row[1],
                "description": row[2],
                "investigator": row[3],
                "created_at": row[4],
                "metadata": json.loads(row[5]) if row[5] else {},
            }

        return {}

    def _get_evidence_inventory(self) -> List[Dict]:
        """Get evidence inventory"""
        case_db = self._locate_workspace_file("cases.db")

        if case_db is None:
            return []

        conn = sqlite3.connect(case_db)
        cursor = conn.cursor()

        case_id = self._get_case_metadata().get("case_id")

        cursor.execute(
            """
            SELECT evidence_id, evidence_type, source_path, description,
                   collected_at, hash_sha256, metadata
            FROM evidence
            WHERE case_id = ?
            ORDER BY evidence_id ASC
        """,
            (case_id,),
        )

        evidence = []
        for row in cursor.fetchall():
            evidence.append(
                {
                    "evidence_id": row[0],
                    "type": row[1],
                    "source_path": row[2],
                    "description": row[3],
                    "collected_at": row[4],
                    "hash_sha256": row[5],
                    "metadata": json.loads(row[6]) if row[6] else {},
                }
            )

        conn.close()
        return evidence

    def _get_all_findings(self) -> List[Dict]:
        """Get all findings from module results"""
        findings = []

        # Scan analysis directories
        analysis_dir = self.case_dir / "analysis"
        if not analysis_dir.exists():
            return findings

        for module_dir in sorted(analysis_dir.iterdir(), key=lambda p: p.name):
            if not module_dir.is_dir():
                continue

            # Look for result files
            for result_file in sorted(module_dir.glob("*.json")):
                try:
                    with open(result_file) as f:
                        result_data = json.load(f)

                        if isinstance(result_data, dict):
                            # Extract findings
                            module_findings = result_data.get("findings", [])
                            for finding in module_findings:
                                finding["module"] = module_dir.name
                                finding["source_file"] = str(result_file)
                                findings.append(finding)
                except Exception as e:
                    self.logger.warning(f"Failed to load {result_file}: {e}")

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(
            key=lambda f: (
                severity_order.get(f.get("severity", "info"), 99),
                f.get("module", ""),
                f.get("description", ""),
                f.get("source_file", ""),
            )
        )

        return findings

    def _get_timeline_data(self) -> Dict[str, Any]:
        """Get timeline events with graceful fallbacks."""
        events: List[Dict[str, Any]] = []
        sources: List[str] = []
        errors: List[str] = []

        # Prefer unified timeline artefacts from the timeline module
        timeline_root = self.case_dir / "timeline"
        if timeline_root.exists():
            for events_file in sorted(timeline_root.glob("**/events.json")):
                try:
                    with events_file.open(encoding="utf-8") as handle:
                        payload = json.load(handle)
                except Exception as exc:
                    errors.append(f"Failed to load {events_file}: {exc}")
                    continue

                if isinstance(payload, list):
                    events.extend(self._normalise_timeline_events(payload))
                    sources.append(str(events_file))

        # Fallback to legacy CSV timelines if no unified events available
        if not events:
            timeline_dirs = [
                self.case_dir / "analysis" / "timeline",
                self.case_dir / "analysis" / "ioc_scan",
            ]

            for timeline_dir in timeline_dirs:
                if not timeline_dir.exists():
                    continue

                for timeline_file in sorted(timeline_dir.glob("*.csv")):
                    try:
                        import csv

                        with timeline_file.open(encoding="utf-8") as handle:
                            reader = csv.DictReader(handle)
                            raw_events = [row for row in reader]
                    except Exception as exc:  # pragma: no cover - legacy fallback
                        errors.append(f"Failed to parse {timeline_file}: {exc}")
                        continue

                    if raw_events:
                        events.extend(self._normalise_timeline_events(raw_events))
                        sources.append(str(timeline_file))

        # Sort and limit the number of events exposed to the report
        events.sort(key=lambda e: e.get("timestamp", ""))

        messages: List[str] = []
        if not timeline_root.exists():
            messages.append("Timeline artefacts were not found for this case.")
        elif not events:
            messages.append(
                "Timeline artefacts were available but contained no events."
            )

        return {
            "events": events[:1000],
            "sources": sources,
            "errors": errors,
            "available": bool(events),
            "messages": messages,
        }

    def _normalise_timeline_events(
        self, records: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        normalised: List[Dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                continue

            timestamp = (
                record.get("timestamp")
                or record.get("datetime")
                or record.get("time")
                or record.get("date")
                or ""
            )
            summary = (
                record.get("summary")
                or record.get("message")
                or record.get("description")
                or record.get("event_description")
                or record.get("type")
                or "Timeline event"
            )
            source = (
                record.get("source") or record.get("module") or record.get("parser")
            )
            event_type = record.get("type") or record.get("event_type")

            normalised.append(
                {
                    "timestamp": timestamp,
                    "summary": summary,
                    "source": source,
                    "type": event_type,
                    "raw": record,
                }
            )

        return normalised

    def _get_network_report_data(self) -> Dict[str, Any]:
        """Aggregate network analysis artefacts for reporting."""
        network_root = self.case_dir / "analysis" / "network"
        summary: Dict[str, Any] = {
            "artifacts": [],
            "top_talkers": [],
            "dns_findings": [],
            "http_findings": [],
            "errors": [],
            "messages": [],
        }

        if not network_root.exists():
            summary["available"] = False
            summary["messages"].append(
                "Network analysis artefacts were not found for this case."
            )
            return summary

        flow_accumulator: Dict[tuple, Dict[str, Any]] = {}
        for network_file in sorted(network_root.glob("**/network.json")):
            try:
                with network_file.open(encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception as exc:
                summary["errors"].append(f"Failed to load {network_file}: {exc}")
                continue

            summary["artifacts"].append(str(network_file))

            flows = payload.get("flows") or []
            if isinstance(flows, list):
                self._collect_top_talkers(flow_accumulator, flows)

            dns_payload = payload.get("dns") or {}
            if isinstance(dns_payload, dict):
                summary["dns_findings"].extend(
                    self._collect_dns_findings(
                        dns_payload.get("suspicious", []), network_file
                    )
                )

            http_payload = payload.get("http") or {}
            if isinstance(http_payload, dict):
                summary["http_findings"].extend(
                    self._collect_http_findings(
                        http_payload.get("requests", []), network_file
                    )
                )

        summary["top_talkers"] = self._finalise_top_talkers(flow_accumulator)
        summary["available"] = bool(summary["artifacts"])
        if not summary["artifacts"]:
            summary["messages"].append(
                "Network module did not produce artefacts for this case."
            )
        elif (
            not summary["top_talkers"]
            and not summary["dns_findings"]
            and not summary["http_findings"]
        ):
            summary["messages"].append(
                "Network artefacts contained no notable findings."
            )
        summary["artifacts"].sort()
        summary["dns_findings"].sort(
            key=lambda item: (
                item.get("timestamp", ""),
                item.get("query", ""),
                item.get("src", ""),
            )
        )
        summary["http_findings"].sort(
            key=lambda item: (
                item.get("timestamp", ""),
                item.get("destination", ""),
                item.get("method", ""),
            )
        )

        return summary

    def _collect_top_talkers(
        self,
        accumulator: Dict[tuple, Dict[str, Any]],
        flows: List[Dict[str, Any]],
    ) -> None:
        for flow in flows:
            if not isinstance(flow, dict):
                continue

            src = flow.get("src") or "unknown"
            dst = flow.get("dst") or "unknown"
            protocol = flow.get("protocol") or "unknown"
            key = (src, dst, protocol)

            entry = accumulator.setdefault(
                key,
                {
                    "src": src,
                    "dst": dst,
                    "protocol": protocol,
                    "bytes": 0,
                    "packets": 0,
                    "flow_count": 0,
                    "first_seen": None,
                    "last_seen": None,
                },
            )

            entry["bytes"] += int(flow.get("bytes", 0) or 0)
            entry["packets"] += int(flow.get("packets", 0) or 0)
            entry["flow_count"] += 1

            start_ts = flow.get("start_ts")
            end_ts = flow.get("end_ts")

            if start_ts and (
                entry["first_seen"] is None or start_ts < entry["first_seen"]
            ):
                entry["first_seen"] = start_ts
            if end_ts and (entry["last_seen"] is None or end_ts > entry["last_seen"]):
                entry["last_seen"] = end_ts

    def _finalise_top_talkers(
        self, accumulator: Dict[tuple, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        talkers = list(accumulator.values())
        talkers.sort(
            key=lambda item: (
                -int(item.get("bytes", 0) or 0),
                -int(item.get("packets", 0) or 0),
                item.get("src", ""),
                item.get("dst", ""),
                item.get("protocol", ""),
            )
        )
        return talkers[:10]

    def _collect_dns_findings(
        self, queries: Any, network_file: Path
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not isinstance(queries, list):
            return findings

        for query in queries:
            if not isinstance(query, dict):
                continue

            heuristics = query.get("heuristics") or {}
            reasons = [
                name.replace("_", " ").title()
                for name, flagged in heuristics.items()
                if flagged
            ]
            findings.append(
                {
                    "query": query.get("query") or "(unknown)",
                    "src": query.get("src") or "unknown",
                    "timestamp": query.get("timestamp") or "",
                    "reason": ", ".join(reasons) if reasons else "Suspicious query",
                    "source_file": str(network_file),
                }
            )

        findings.sort(
            key=lambda item: (
                item.get("timestamp", ""),
                item.get("query", ""),
                item.get("src", ""),
            )
        )
        return findings[:20]

    def _collect_http_findings(
        self, requests: Any, network_file: Path
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not isinstance(requests, list):
            return findings

        indicator_labels = {
            "suspicious_user_agent": "Suspicious user agent",
            "encoded_uri": "Encoded URI",
            "uncommon_method": "Uncommon method",
        }

        for request in requests:
            if not isinstance(request, dict):
                continue

            indicators = request.get("indicators") or {}
            flagged = [
                indicator_labels.get(name, name)
                for name, value in indicators.items()
                if value
            ]

            if not flagged:
                continue

            host = request.get("host") or ""
            uri = request.get("uri") or ""
            if host and uri:
                destination = f"{host}{uri}"
            else:
                destination = host or uri or "(unknown)"

            findings.append(
                {
                    "timestamp": request.get("timestamp") or "",
                    "method": (request.get("method") or "").upper(),
                    "destination": destination,
                    "src": request.get("src") or "unknown",
                    "indicators": ", ".join(flagged),
                    "source_file": str(network_file),
                }
            )

        findings.sort(
            key=lambda item: (
                item.get("timestamp", ""),
                item.get("destination", ""),
                item.get("method", ""),
            )
        )
        return findings[:20]

    def _get_coc_events(self) -> List[Dict]:
        """Get Chain of Custody events"""
        coc_db = self._locate_workspace_file("chain_of_custody.db")

        if coc_db is None:
            return []

        conn = sqlite3.connect(coc_db)
        cursor = conn.cursor()

        case_id = self._get_case_metadata().get("case_id")

        cursor.execute(
            """
            SELECT event_id, timestamp, event_type, evidence_id, actor,
                   action, description, metadata
            FROM coc_events
            WHERE case_id = ?
            ORDER BY timestamp ASC
        """,
            (case_id,),
        )

        events = []
        for row in cursor.fetchall():
            events.append(
                {
                    "event_id": row[0],
                    "timestamp": row[1],
                    "event_type": row[2],
                    "evidence_id": row[3],
                    "actor": row[4],
                    "action": row[5],
                    "description": row[6],
                    "metadata": json.loads(row[7]) if row[7] else {},
                }
            )

        conn.close()
        return events

    def _generate_executive_summary(self) -> Dict:
        """Generate executive summary"""
        findings = self._get_all_findings()
        evidence = self._get_evidence_inventory()

        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Key findings (top 5 critical/high)
        key_findings = [
            f for f in findings if f.get("severity") in ["critical", "high"]
        ][:5]

        return {
            "total_evidence": len(evidence),
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "key_findings": key_findings,
            "analysis_complete": True,
        }

    def _calculate_statistics(self, data: Dict) -> Dict:
        """Calculate report statistics"""
        stats = {}

        if "findings" in data:
            stats["total_findings"] = len(data["findings"])

            # By type
            types = {}
            for f in data["findings"]:
                ftype = f.get("type", "unknown")
                types[ftype] = types.get(ftype, 0) + 1
            stats["findings_by_type"] = types

            # By module
            modules = {}
            for f in data["findings"]:
                module = f.get("module", "unknown")
                modules[module] = modules.get(module, 0) + 1
            stats["findings_by_module"] = modules

        if "evidence" in data:
            stats["total_evidence"] = len(data["evidence"])

        if "timeline" in data and isinstance(data["timeline"], dict):
            stats["timeline_events"] = len(data["timeline"].get("events", []))

        if "network" in data and isinstance(data["network"], dict):
            network = data["network"]
            stats["network_artifacts"] = len(network.get("artifacts", []))
            stats["network_top_talkers"] = len(network.get("top_talkers", []))
            stats["network_dns_findings"] = len(network.get("dns_findings", []))
            stats["network_http_findings"] = len(network.get("http_findings", []))

        if "chain_of_custody" in data:
            stats["coc_events"] = len(data["chain_of_custody"])

        return stats

    def _generate_html_report(
        self,
        data: Dict,
        output_path: Path,
        alerts: List[str],
        metadata: Dict[str, Any],
    ) -> Path:
        """Generate HTML report"""
        target = output_path
        target.parent.mkdir(parents=True, exist_ok=True)

        metadata["html_template"] = self.template_name
        metadata["html_template_available"] = self.templates_available

        if not self.templates_available:
            alerts_message = (
                "Report templates missing; generated minimal HTML output instead."
            )
            self.logger.warning(alerts_message)
            self._append_alert(alerts, alerts_message)
            target.write_text(self._render_minimal_html(data), encoding="utf-8")
            metadata["html_template_fallback"] = True
            self.logger.info(f"HTML report generated with fallback template: {target}")
            return target

        try:
            export_report(data, "html", target)
        except Exception as exc:  # pragma: no cover - guarded fallback
            message = "HTML template rendering failed; generated minimal HTML instead."
            self.logger.warning("%s (%s)", message, exc)
            self._append_alert(alerts, message)
            target.write_text(self._render_minimal_html(data), encoding="utf-8")
            metadata["html_template_fallback"] = True
        else:
            metadata["html_template_fallback"] = False

        self.logger.info(f"HTML report generated: {target}")
        return target

    def _generate_pdf_report(
        self,
        html_path: Path,
        output_path: Path,
        alerts: List[str],
        metadata: Dict[str, Any],
    ) -> Optional[Path]:
        """Convert an existing HTML report to PDF with graceful fallbacks."""

        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            export_pdf(html_path, output_path)
        except Exception as exc:  # pragma: no cover - optional dependency failures
            self.logger.warning("PDF conversion failed: %s", exc)
            metadata["pdf_error"] = str(exc)
            return None

        self.logger.info(f"PDF report generated: {output_path}")
        return output_path

    def _generate_json_report(self, data: Dict, output_file: Optional[str]) -> Path:
        """Generate JSON report"""
        if not output_file:
            output_file = self.output_dir / f"report_{utc_slug()}.json"
        else:
            output_file = Path(output_file)

        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str, sort_keys=True)

        self.logger.info(f"JSON report generated: {output_file}")
        return output_file

    def _generate_markdown_report(self, data: Dict, output_file: Optional[str]) -> Path:
        """Generate Markdown report"""
        if not output_file:
            output_file = self.output_dir / f"report_{utc_slug()}.md"
        else:
            output_file = Path(output_file)

        md_lines = []

        # Header
        case = data.get("case", {})
        md_lines.append("# Forensic Investigation Report")
        md_lines.append(f"\n## {case.get('name', 'N/A')}")
        md_lines.append(f"\n**Case ID:** {case.get('case_id', 'N/A')}")
        md_lines.append(f"**Investigator:** {case.get('investigator', 'N/A')}")
        md_lines.append(f"**Created:** {case.get('created_at', 'N/A')}")

        if case.get("description"):
            md_lines.append(f"\n**Description:** {case['description']}")

        # Executive Summary
        if "executive_summary" in data:
            es = data["executive_summary"]
            md_lines.append("\n## Executive Summary")
            md_lines.append(f"\n- **Evidence Items:** {es.get('total_evidence', 0)}")
            md_lines.append(f"- **Total Findings:** {es.get('total_findings', 0)}")

            sev = es.get("severity_breakdown", {})
            md_lines.append(f"- **Critical:** {sev.get('critical', 0)}")
            md_lines.append(f"- **High:** {sev.get('high', 0)}")
            md_lines.append(f"- **Medium:** {sev.get('medium', 0)}")

        # Evidence
        if "evidence" in data:
            md_lines.append("\n## Evidence Inventory")
            for ev in data["evidence"]:
                md_lines.append(f"\n### {ev.get('evidence_id')}")
                md_lines.append(f"- **Type:** {ev.get('type')}")
                md_lines.append(f"- **Description:** {ev.get('description')}")
                md_lines.append(f"- **Collected:** {ev.get('collected_at')}")
                md_lines.append(f"- **Hash:** `{ev.get('hash_sha256', '')[:32]}...`")

        # Findings
        if "findings" in data:
            md_lines.append("\n## Analysis Findings")
            for f in data["findings"]:
                severity = f.get("severity", "info").upper()
                md_lines.append(
                    f"\n### [{severity}] {f.get('description', f.get('type'))}"
                )
                md_lines.append(f"\n**Module:** {f.get('module')}")
                if f.get("file_path"):
                    md_lines.append(f"**File:** `{f.get('file_path')}`")
                if f.get("context"):
                    md_lines.append(f"\n{f.get('context')[:200]}")

        # Write file
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines))

        self.logger.info(f"Markdown report generated: {output_file}")
        return output_file

    def _prepare_output_path(
        self,
        output_file: Optional[str],
        base_name: str,
        extension: str,
    ) -> Tuple[Optional[Path], Optional[str]]:
        """Resolve the output path honouring config defaults and collisions."""

        ext = extension if extension.startswith(".") else f".{extension}"

        if output_file:
            candidate = Path(output_file)
            if not candidate.is_absolute():
                candidate = self.output_dir / candidate
            if not candidate.suffix:
                candidate = candidate.with_suffix(ext)
            if candidate.exists():
                return (
                    None,
                    f"Output file {candidate} already exists; refusing to overwrite.",
                )
            return candidate, None

        default_candidate = self.output_dir / f"{base_name}{ext}"
        return self._ensure_unique_path(default_candidate), None

    def _ensure_unique_path(self, candidate: Path) -> Path:
        """Ensure ``candidate`` does not collide with an existing artefact."""

        path = candidate
        counter = 1
        while path.exists():
            path = candidate.with_name(f"{candidate.stem}_{counter}{candidate.suffix}")
            counter += 1
        return path

    def _collect_section_alerts(
        self, report_data: Dict[str, Any], alerts: List[str]
    ) -> None:
        """Collect informational alerts for missing sections."""

        timeline = report_data.get("timeline")
        if isinstance(timeline, dict):
            for message in timeline.get("messages", []) or []:
                self._append_alert(alerts, message)

        network = report_data.get("network")
        if isinstance(network, dict):
            for message in network.get("messages", []) or []:
                self._append_alert(alerts, message)

    def _append_alert(self, alerts: List[str], message: str) -> None:
        """Append ``message`` to ``alerts`` without duplicates."""

        if message and message not in alerts:
            alerts.append(message)

    def _timestamp_to_slug(self, timestamp: str) -> str:
        """Create a deterministic slug from an ISO-8601 timestamp."""

        safe = timestamp.replace(":", "").replace("-", "")
        safe = safe.replace("T", "_").replace(".", "")
        safe = safe.replace("+", "p").replace("Z", "z")
        return safe

    def _render_minimal_html(self, data: Dict[str, Any]) -> str:
        """Render a minimal HTML report without external templates."""

        case = data.get("case", {}) if isinstance(data, dict) else {}
        alerts = data.get("alerts") if isinstance(data, dict) else None
        statistics = data.get("statistics") if isinstance(data, dict) else None

        title = escape(case.get("name") or case.get("case_id") or "Forensic Report")
        investigator = escape(case.get("investigator", "n/a"))
        created_at = escape(case.get("created_at", "n/a"))
        description = case.get("description")

        alert_html = ""
        if alerts:
            items = "".join(f"<li>{escape(str(item))}</li>" for item in alerts)
            alert_html = (
                '<section><h2>Notices</h2><ul class="notices">'
                f"{items}</ul></section>"
            )

        stats_html = ""
        if isinstance(statistics, dict) and statistics:
            stats_items = "".join(
                f"<li><strong>{escape(str(key))}:</strong> "
                f"{escape(str(value))}</li>"
                for key, value in sorted(statistics.items())
            )
            stats_html = (
                '<section><h2>At a Glance</h2><ul class="stats">'
                f"{stats_items}</ul></section>"
            )

        description_html = (
            f'<p class="case-description">{escape(description)}</p>'
            if description
            else ""
        )

        return f"""<!DOCTYPE html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\">
    <title>Forensic Investigation Report — {title}</title>
    <style>
      body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #111827; }}
      header {{ margin-bottom: 1.5rem; }}
      h1 {{ font-size: 2rem; margin: 0; }}
      .metadata {{ color: #4b5563; margin: 0.35rem 0 0 0; }}
      section {{ margin-top: 1.5rem; }}
      ul.notices, ul.stats {{ padding-left: 1.25rem; }}
      ul.notices li {{ background: #e0f2fe; border-left: 4px solid #0284c7; padding: 0.5rem 0.75rem; margin-bottom: 0.5rem; list-style: none; }}
      ul.stats li {{ margin-bottom: 0.35rem; }}
      .case-description {{ margin-top: 0.75rem; color: #374151; }}
    </style>
  </head>
  <body>
    <header>
      <h1>Forensic Investigation Report</h1>
      <p class=\"metadata\">Investigator: {investigator} · Created: {created_at}</p>
      {description_html}
    </header>
    {alert_html}
    {stats_html}
  </body>
</html>
"""
