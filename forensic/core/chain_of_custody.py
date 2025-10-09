#!/usr/bin/env python3
"""
Chain of Custody Management
Tracks all evidence handling and maintains audit trail
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List

from forensic.core.time_utils import utc_isoformat


class ChainOfCustody:
    """
    Chain of Custody tracker

    Maintains immutable audit trail of all evidence handling,
    access, and modifications.

    Events logged:
    - Evidence collection
    - Evidence access
    - Evidence modification
    - Evidence transfer
    - Analysis execution
    - Report generation
    """

    def __init__(self, db_path: Path):
        """
        Initialize CoC tracker

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS coc_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                case_id TEXT,
                evidence_id TEXT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                description TEXT,
                metadata TEXT,
                integrity_hash TEXT,
                previous_event_id INTEGER,
                FOREIGN KEY (previous_event_id) REFERENCES coc_events(event_id)
            )
        """
        )

        # Index for fast queries
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_case_id ON coc_events(case_id)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_evidence_id ON coc_events(evidence_id)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_timestamp ON coc_events(timestamp)
        """
        )

        conn.commit()
        conn.close()

    def log_event(
        self,
        event_type: str,
        actor: str,
        action: str = None,
        description: str = None,
        case_id: str = None,
        evidence_id: str = None,
        metadata: Dict[str, Any] = None,
        integrity_hash: str = None,
    ) -> int:
        """
        Log a chain of custody event

        Args:
            event_type: Type of event (COLLECTED, ACCESSED, MODIFIED, etc.)
            actor: Person/system performing action
            action: Specific action taken
            description: Human-readable description
            case_id: Related case ID
            evidence_id: Related evidence ID
            metadata: Additional event metadata
            integrity_hash: Evidence hash at time of event

        Returns:
            Event ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        timestamp = utc_isoformat()

        # Get previous event ID for this evidence (if any)
        previous_event_id = None
        if evidence_id:
            cursor.execute(
                "SELECT event_id FROM coc_events WHERE evidence_id = ? ORDER BY event_id DESC LIMIT 1",
                (evidence_id,),
            )
            result = cursor.fetchone()
            if result:
                previous_event_id = result[0]

        # Construct action if not provided
        if action is None:
            action = event_type.lower().replace("_", " ")

        cursor.execute(
            """
            INSERT INTO coc_events (
                timestamp, event_type, case_id, evidence_id, actor,
                action, description, metadata, integrity_hash, previous_event_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                event_type,
                case_id,
                evidence_id,
                actor,
                action,
                description,
                json.dumps(metadata, sort_keys=True) if metadata else None,
                integrity_hash,
                previous_event_id,
            ),
        )

        event_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return event_id

    def get_evidence_chain(self, evidence_id: str) -> List[Dict]:
        """
        Get complete chain of custody for evidence

        Args:
            evidence_id: Evidence ID

        Returns:
            List of events in chronological order
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT event_id, timestamp, event_type, actor, action,
                   description, metadata, integrity_hash, previous_event_id
            FROM coc_events
            WHERE evidence_id = ?
            ORDER BY timestamp ASC
            """,
            (evidence_id,),
        )

        events = []
        for row in cursor.fetchall():
            events.append(
                {
                    "event_id": row[0],
                    "timestamp": row[1],
                    "event_type": row[2],
                    "actor": row[3],
                    "action": row[4],
                    "description": row[5],
                    "metadata": json.loads(row[6]) if row[6] else {},
                    "integrity_hash": row[7],
                    "previous_event_id": row[8],
                }
            )

        conn.close()
        return events

    def get_case_chain(self, case_id: str) -> List[Dict]:
        """
        Get all chain of custody events for a case

        Args:
            case_id: Case ID

        Returns:
            List of events in chronological order
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT event_id, timestamp, event_type, evidence_id, actor,
                   action, description, metadata, integrity_hash
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
                    "integrity_hash": row[8],
                }
            )

        conn.close()
        return events

    def verify_chain_integrity(self, evidence_id: str) -> tuple:
        """
        Verify chain of custody integrity

        Checks:
        - No gaps in event sequence
        - Proper linking between events
        - Hash consistency

        Args:
            evidence_id: Evidence ID

        Returns:
            (is_valid, issues)
        """
        events = self.get_evidence_chain(evidence_id)

        if not events:
            return False, ["No chain of custody events found"]

        issues = []

        # Check event sequence
        for i in range(1, len(events)):
            prev_event = events[i - 1]
            curr_event = events[i]

            # Check if previous_event_id links correctly
            if curr_event["previous_event_id"] != prev_event["event_id"]:
                issues.append(
                    f"Event {curr_event['event_id']}: Broken link to previous event"
                )

            # Check timestamps are in order
            if curr_event["timestamp"] < prev_event["timestamp"]:
                issues.append(f"Event {curr_event['event_id']}: Timestamp out of order")

        # Check hash consistency
        last_hash = None
        for event in events:
            if event["integrity_hash"]:
                if last_hash and last_hash != event["integrity_hash"]:
                    if event["event_type"] not in ["MODIFIED", "PROCESSED"]:
                        issues.append(
                            f"Event {event['event_id']}: Hash mismatch without modification"
                        )
                last_hash = event["integrity_hash"]

        is_valid = len(issues) == 0
        return is_valid, issues

    def export_chain(
        self,
        case_id: str = None,
        evidence_id: str = None,
        output_path: Path = None,
        format: str = "json",
    ):
        """
        Export chain of custody

        Args:
            case_id: Case ID (optional)
            evidence_id: Evidence ID (optional)
            output_path: Output file path
            format: Export format (json, csv, html)
        """
        if evidence_id:
            events = self.get_evidence_chain(evidence_id)
        elif case_id:
            events = self.get_case_chain(case_id)
        else:
            raise ValueError("Must provide either case_id or evidence_id")

        events_sorted = sorted(
            events,
            key=lambda item: (
                item.get("timestamp") or "",
                item.get("event_id") or "",
            ),
        )

        if format == "json":
            output = json.dumps(events_sorted, indent=2, sort_keys=True)
        elif format == "csv":
            import csv
            import io

            output_buffer = io.StringIO()
            writer = csv.DictWriter(
                output_buffer,
                fieldnames=[
                    "event_id",
                    "timestamp",
                    "event_type",
                    "actor",
                    "action",
                    "description",
                ],
            )
            writer.writeheader()
            for event in events_sorted:
                writer.writerow({k: event.get(k, "") for k in writer.fieldnames})
            output = output_buffer.getvalue()
        elif format == "html":
            output = self._generate_html_report(events)
        else:
            raise ValueError(f"Unsupported format: {format}")

        if output_path:
            with open(output_path, "w") as f:
                f.write(output)

        return output

    def _generate_html_report(self, events: List[Dict]) -> str:
        """Generate HTML chain of custody report"""
        html = (
            """
<!DOCTYPE html>
<html>
<head>
    <title>Chain of Custody Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #4CAF50; color: white; padding: 12px; text-align: left; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .timestamp { font-family: monospace; }
        .hash { font-family: monospace; font-size: 0.8em; word-break: break-all; }
    </style>
</head>
<body>
    <h1>Chain of Custody Report</h1>
    <p>Generated: """
            + utc_isoformat()
            + """</p>
    <p>Total Events: """
            + str(len(events))
            + """</p>
    
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Event Type</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Description</th>
            <th>Hash</th>
        </tr>
"""
        )

        for event in events:
            html += f"""
        <tr>
            <td class="timestamp">{event['timestamp']}</td>
            <td>{event['event_type']}</td>
            <td>{event['actor']}</td>
            <td>{event['action']}</td>
            <td>{event.get('description', '')}</td>
            <td class="hash">{event.get('integrity_hash', '')[:16]}...</td>
        </tr>
"""

        html += """
    </table>
</body>
</html>
"""
        return html

    def get_statistics(self, case_id: str = None) -> Dict:
        """
        Get chain of custody statistics

        Args:
            case_id: Optional case ID to filter by

        Returns:
            Statistics dictionary
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        where_clause = "WHERE case_id = ?" if case_id else ""
        params = (case_id,) if case_id else ()

        # Total events
        cursor.execute(f"SELECT COUNT(*) FROM coc_events {where_clause}", params)
        total_events = cursor.fetchone()[0]

        # Events by type
        cursor.execute(
            f"SELECT event_type, COUNT(*) FROM coc_events {where_clause} GROUP BY event_type",
            params,
        )
        events_by_type = dict(cursor.fetchall())

        # Unique actors
        cursor.execute(
            f"SELECT COUNT(DISTINCT actor) FROM coc_events {where_clause}", params
        )
        unique_actors = cursor.fetchone()[0]

        # Unique evidence
        evidence_clause = (
            f"{where_clause} AND evidence_id IS NOT NULL"
            if case_id
            else "WHERE evidence_id IS NOT NULL"
        )
        cursor.execute(
            f"SELECT COUNT(DISTINCT evidence_id) FROM coc_events {evidence_clause}",
            params,
        )
        unique_evidence = cursor.fetchone()[0]

        conn.close()

        return {
            "total_events": total_events,
            "events_by_type": events_by_type,
            "unique_actors": unique_actors,
            "unique_evidence": unique_evidence,
        }
