#!/usr/bin/env python3
"""
Report Generation Module
HTML and PDF report generation from forensic analysis results

Features:
- HTML report generation with templates
- PDF export support
- Timeline visualization
- Evidence summary
- Chain of Custody integration
- Finding severity categorization
- Interactive charts and graphs
- Multiple report templates
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

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

        report_format = params.get("format", "html").lower()
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

        findings = []
        errors = []
        metadata = {"requested_format": report_format, "generation_start": timestamp}

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

            metadata["sections"] = list(report_data.keys())
            metadata["output_format"] = report_format

            default_ext = {
                "html": "html",
                "pdf": "pdf",
                "json": "json",
                "md": "md",
                "markdown": "md",
            }.get(report_format, "html")
            target_path = (
                Path(output_file)
                if output_file
                else self.output_dir / f"report.{default_ext}"
            )
            metadata["output_path"] = str(target_path)

            if dry_run:
                metadata["dry_run"] = True
                findings.append(
                    {
                        "type": "dry_run",
                        "description": f"Prepared {report_format.upper()} report",
                        "output_file": str(target_path),
                    }
                )
                output_path = None
            elif report_format in {"json", "md", "markdown"}:
                fmt = "json" if report_format == "json" else "md"
                output_path = export_report(report_data, fmt, target_path)
            elif report_format == "html":
                output_path = self._generate_html_report(report_data, str(target_path))
            elif report_format == "pdf":
                renderer = get_pdf_renderer()
                metadata["pdf_renderer"] = renderer
                if renderer:
                    output_path = self._generate_pdf_report(
                        report_data, str(target_path)
                    )
                else:
                    fallback_target = target_path.with_suffix(".html")
                    metadata["output_format"] = "html"
                    metadata["fallback_format"] = "html"
                    metadata["output_path"] = str(fallback_target)
                    self.logger.warning(
                        "PDF renderer not available; generating HTML report instead."
                    )
                    output_path = self._generate_html_report(
                        report_data, str(fallback_target)
                    )
                    findings.append(
                        {
                            "type": "pdf_renderer_unavailable",
                            "description": (
                                "PDF renderer not available; generated HTML report instead."
                            ),
                            "output_file": str(output_path),
                        }
                    )
            else:
                errors.append(f"Unsupported report format: {report_format}")
                return ModuleResult(
                    result_id=result_id,
                    module_name=self.name,
                    status="failed",
                    timestamp=timestamp,
                    findings=findings,
                    metadata=metadata,
                    errors=errors,
                )

            if output_path:
                metadata["output_path"] = str(output_path)

            result_format = metadata.get("output_format", report_format)

            if not dry_run:
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

    def _get_case_metadata(self) -> Dict:
        """Get case metadata from database"""
        case_db = self.case_dir.parent.parent.parent / "cases.db"

        if not case_db.exists():
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
        case_db = self.case_dir.parent.parent.parent / "cases.db"

        if not case_db.exists():
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

        for module_dir in analysis_dir.iterdir():
            if not module_dir.is_dir():
                continue

            # Look for result files
            for result_file in module_dir.glob("*.json"):
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
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 99))

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

                for timeline_file in timeline_dir.glob("*.csv"):
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

        return {
            "events": events[:1000],
            "sources": sources,
            "errors": errors,
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
        }

        if not network_root.exists():
            summary["available"] = False
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
            key=lambda item: (item.get("bytes", 0), item.get("packets", 0)),
            reverse=True,
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

        findings.sort(key=lambda item: item.get("timestamp", ""))
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

        findings.sort(key=lambda item: item.get("timestamp", ""))
        return findings[:20]

    def _get_coc_events(self) -> List[Dict]:
        """Get Chain of Custody events"""
        coc_db = self.case_dir.parent.parent.parent / "chain_of_custody.db"

        if not coc_db.exists():
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

    def _generate_html_report(self, data: Dict, output_file: Optional[str]) -> Path:
        """Generate HTML report"""
        target = (
            self.output_dir / f"report_{utc_slug()}.html"
            if not output_file
            else Path(output_file)
        )

        target.parent.mkdir(parents=True, exist_ok=True)

        export_report(data, "html", target)

        self.logger.info(f"HTML report generated: {target}")
        return target

    def _generate_pdf_report(self, data: Dict, output_file: Optional[str]) -> Path:
        """Generate PDF report"""
        # First generate HTML
        html_file = self._generate_html_report(data, None)

        if not output_file:
            output_file = self.output_dir / f"report_{utc_slug()}.pdf"
        else:
            output_file = Path(output_file)

        # Convert HTML to PDF using available renderer
        try:
            export_pdf(html_file, output_file)
        except Exception as e:  # pragma: no cover - passthrough for conversion errors
            raise RuntimeError(f"PDF generation failed: {e}") from e

        self.logger.info(f"PDF report generated: {output_file}")
        return output_file

    def _generate_json_report(self, data: Dict, output_file: Optional[str]) -> Path:
        """Generate JSON report"""
        if not output_file:
            output_file = self.output_dir / f"report_{utc_slug()}.json"
        else:
            output_file = Path(output_file)

        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

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
