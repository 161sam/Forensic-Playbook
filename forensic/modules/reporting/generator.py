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
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ...core.evidence import Evidence
from ...core.module import ModuleResult, ReportingModule
from ...core.time_utils import utc_display, utc_isoformat, utc_slug
from .exporter import export_report


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
        metadata = {"format": report_format, "generation_start": timestamp}

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
                output_path = self._generate_pdf_report(report_data, str(target_path))
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

            if not dry_run:
                findings.append(
                    {
                        "type": "report_generated",
                        "description": f"{report_format.upper()} report generated successfully",
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

    def _get_timeline_data(self) -> List[Dict]:
        """Get timeline events"""
        timeline_events = []

        # Look for timeline files
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

                    with open(timeline_file) as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            if "timestamp" in row:
                                timeline_events.append(row)
                except Exception:
                    pass

        # Sort by timestamp
        timeline_events.sort(key=lambda e: e.get("timestamp", ""))

        return timeline_events[:1000]  # Limit to 1000 events

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

        if "timeline" in data:
            stats["timeline_events"] = len(data["timeline"])

        if "chain_of_custody" in data:
            stats["coc_events"] = len(data["chain_of_custody"])

        return stats

    def _generate_html_report(self, data: Dict, output_file: Optional[str]) -> Path:
        """Generate HTML report"""
        if not output_file:
            output_file = self.output_dir / f"report_{utc_slug()}.html"
        else:
            output_file = Path(output_file)

        # Create HTML template
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Investigation Report - {{ case.name }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        header p { font-size: 1.1em; opacity: 0.9; }
        .metadata {
            background: #f8f9fa;
            padding: 20px;
            border-left: 4px solid #667eea;
            margin: 20px;
        }
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .metadata-item strong { display: block; color: #667eea; font-size: 0.9em; }
        .section {
            padding: 30px;
            border-bottom: 1px solid #eee;
        }
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card .number { font-size: 2.5em; font-weight: bold; }
        .stat-card .label { font-size: 0.9em; opacity: 0.9; }
        .finding {
            background: #fff;
            border: 1px solid #ddd;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .finding.critical { border-left-color: #dc3545; background: #fff5f5; }
        .finding.high { border-left-color: #fd7e14; background: #fff9f0; }
        .finding.medium { border-left-color: #ffc107; background: #fffbf0; }
        .finding.low { border-left-color: #28a745; background: #f0fff4; }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-badge.critical { background: #dc3545; color: white; }
        .severity-badge.high { background: #fd7e14; color: white; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #28a745; color: white; }
        .severity-badge.info { background: #17a2b8; color: white; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #667eea;
        }
        tr:hover { background: #f8f9fa; }
        .timeline-event {
            padding: 10px;
            margin: 8px 0;
            border-left: 3px solid #667eea;
            background: #f8f9fa;
        }
        .timestamp { color: #666; font-size: 0.9em; font-family: monospace; }
        footer {
            background: #2c3e50;
            color: white;
            padding: 30px;
            text-align: center;
        }
        .warning { 
            background: #fff3cd; 
            border: 1px solid #ffc107; 
            padding: 15px; 
            margin: 15px 0; 
            border-radius: 4px; 
        }
        @media print {
            .container { box-shadow: none; }
            .section { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Forensic Investigation Report</h1>
            <p>{{ case.name }}</p>
        </header>

        <div class="metadata">
            <h3>Case Information</h3>
            <div class="metadata-grid">
                <div class="metadata-item">
                    <strong>Case ID:</strong>
                    {{ case.case_id }}
                </div>
                <div class="metadata-item">
                    <strong>Investigator:</strong>
                    {{ case.investigator }}
                </div>
                <div class="metadata-item">
                    <strong>Created:</strong>
                    {{ case.created_at }}
                </div>
                <div class="metadata-item">
                    <strong>Report Generated:</strong>
                    {{ statistics.report_time or "N/A" }}
                </div>
            </div>
            {% if case.description %}
            <p style="margin-top: 15px;"><strong>Description:</strong> {{ case.description }}</p>
            {% endif %}
        </div>

        {% if executive_summary %}
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="number">{{ executive_summary.total_evidence }}</div>
                    <div class="label">Evidence Items</div>
                </div>
                <div class="stat-card">
                    <div class="number">{{ executive_summary.total_findings }}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="stat-card">
                    <div class="number">{{ executive_summary.severity_breakdown.get('critical', 0) + executive_summary.severity_breakdown.get('high', 0) }}</div>
                    <div class="label">Critical/High Severity</div>
                </div>
            </div>

            {% if executive_summary.key_findings %}
            <h3 style="margin-top: 20px;">Key Findings</h3>
            {% for finding in executive_summary.key_findings %}
            <div class="finding {{ finding.severity }}">
                <div class="finding-header">
                    <strong>{{ finding.description or finding.type }}</strong>
                    <span class="severity-badge {{ finding.severity }}">{{ finding.severity }}</span>
                </div>
                {% if finding.context %}
                <p style="margin-top: 8px; color: #666;">{{ finding.context[:200] }}...</p>
                {% endif %}
            </div>
            {% endfor %}
            {% endif %}
        </div>
        {% endif %}

        {% if evidence %}
        <div class="section">
            <h2>📦 Evidence Inventory</h2>
            <table>
                <thead>
                    <tr>
                        <th>Evidence ID</th>
                        <th>Type</th>
                        <th>Description</th>
                        <th>Collected</th>
                        <th>Hash (SHA256)</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in evidence %}
                    <tr>
                        <td><code>{{ item.evidence_id }}</code></td>
                        <td>{{ item.type }}</td>
                        <td>{{ item.description }}</td>
                        <td>{{ item.collected_at }}</td>
                        <td><code style="font-size: 0.8em;">{{ item.hash_sha256[:16] }}...</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if findings %}
        <div class="section">
            <h2>🔎 Analysis Findings</h2>
            <p>Total findings: {{ findings|length }}</p>
            
            {% for finding in findings %}
            <div class="finding {{ finding.severity or 'info' }}">
                <div class="finding-header">
                    <div>
                        <strong>{{ finding.description or finding.type }}</strong>
                        <span style="color: #666; font-size: 0.9em; margin-left: 10px;">[{{ finding.module }}]</span>
                    </div>
                    <span class="severity-badge {{ finding.severity or 'info' }}">
                        {{ finding.severity or 'info' }}
                    </span>
                </div>
                
                {% if finding.file_path %}
                <p style="margin-top: 8px;"><strong>File:</strong> <code>{{ finding.file_path }}</code></p>
                {% endif %}
                
                {% if finding.context %}
                <p style="margin-top: 8px; color: #666;">{{ finding.context[:300] }}</p>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if timeline and timeline|length > 0 %}
        <div class="section">
            <h2>📅 Timeline</h2>
            <p>Showing {{ timeline|length }} events</p>
            {% for event in timeline[:100] %}
            <div class="timeline-event">
                <div class="timestamp">{{ event.timestamp }}</div>
                <div>{{ event.description or event.type or 'Event' }}</div>
                {% if event.file_path %}
                <div style="font-size: 0.9em; color: #666;">{{ event.file_path }}</div>
                {% endif %}
            </div>
            {% endfor %}
            {% if timeline|length > 100 %}
            <p style="margin-top: 15px; font-style: italic; color: #666;">
                Showing first 100 of {{ timeline|length }} events. See full timeline in analysis files.
            </p>
            {% endif %}
        </div>
        {% endif %}

        {% if chain_of_custody %}
        <div class="section">
            <h2>🔒 Chain of Custody</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>Actor</th>
                        <th>Action</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {% for event in chain_of_custody %}
                    <tr>
                        <td class="timestamp">{{ event.timestamp }}</td>
                        <td>{{ event.event_type }}</td>
                        <td>{{ event.actor }}</td>
                        <td>{{ event.action }}</td>
                        <td>{{ event.description }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <footer>
            <p><strong>Forensic-Playbook v2.0</strong></p>
            <p>Digital Forensics Investigation Framework</p>
            <p style="margin-top: 10px; font-size: 0.9em; opacity: 0.8;">
                Generated on {{ statistics.report_time or 'N/A' }}
            </p>
        </footer>
    </div>
</body>
</html>
"""

        # Render template
        from jinja2 import Template

        template = Template(html_template)

        # Add current datetime if not present
        data["statistics"]["report_time"] = utc_display()

        html_content = template.render(**data)

        # Write to file
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        self.logger.info(f"HTML report generated: {output_file}")
        return output_file

    def _generate_pdf_report(self, data: Dict, output_file: Optional[str]) -> Path:
        """Generate PDF report"""
        # First generate HTML
        html_file = self._generate_html_report(data, None)

        if not output_file:
            output_file = self.output_dir / f"report_{utc_slug()}.pdf"
        else:
            output_file = Path(output_file)

        # Convert HTML to PDF using wkhtmltopdf or weasyprint
        try:
            if self._verify_tool("wkhtmltopdf"):
                subprocess.run(
                    [
                        "wkhtmltopdf",
                        "--enable-local-file-access",
                        str(html_file),
                        str(output_file),
                    ],
                    check=True,
                    timeout=300,
                )
            else:
                # Try weasyprint
                try:
                    from weasyprint import HTML

                    HTML(filename=str(html_file)).write_pdf(output_file)
                except ImportError as exc:
                    raise RuntimeError(
                        "PDF generation requires wkhtmltopdf or weasyprint"
                    ) from exc

            self.logger.info(f"PDF report generated: {output_file}")
            return output_file

        except Exception as e:
            raise RuntimeError(f"PDF generation failed: {e}") from e

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
