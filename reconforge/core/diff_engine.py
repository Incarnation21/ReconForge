"""
Continuous Monitoring and State Diffing Engine for ReconForge.
Stores historical scan snapshots in a lightweight SQLite database, calculates
attack surface deltas (new subdomains, opened/closed ports, newly introduced
vulnerabilities, resolved findings), and enables continuous asset monitoring.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from reconforge.core.models import ScanResult

logger = logging.getLogger(__name__)

DEFAULT_DB_FILENAME = "reconforge_history.db"


@dataclass
class ScanDelta:
    """Represents the difference between two chronological scans."""
    target: str
    prev_scan_id: Optional[str]
    curr_scan_id: str
    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    new_ports: dict[str, list[int]] = field(default_factory=dict)       # hostname -> [ports]
    closed_ports: dict[str, list[int]] = field(default_factory=dict)    # hostname -> [ports]
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = field(default_factory=list)
    status_changes: list[dict[str, Any]] = field(default_factory=list)

    def has_changes(self) -> bool:
        return bool(
            self.new_hosts
            or self.removed_hosts
            or self.new_ports
            or self.closed_ports
            or self.new_findings
            or self.resolved_findings
            or self.status_changes
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "prev_scan_id": self.prev_scan_id,
            "curr_scan_id": self.curr_scan_id,
            "has_changes": self.has_changes(),
            "new_hosts": self.new_hosts,
            "removed_hosts": self.removed_hosts,
            "new_ports": self.new_ports,
            "closed_ports": self.closed_ports,
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "status_changes": self.status_changes,
        }

    def to_summary_text(self) -> str:
        """Render a readable terminal delta diff."""
        lines = []
        lines.append("=" * 60)
        lines.append(f" RECONFORGE ASSET DIFF: {self.target}")
        lines.append(f" Comparison: {self.prev_scan_id or 'BASELINE'} -> {self.curr_scan_id}")
        lines.append("=" * 60)

        if not self.has_changes():
            lines.append(" [*] No changes detected in attack surface.")
            lines.append("=" * 60)
            return "\n".join(lines)

        if self.new_hosts:
            lines.append(f" [+] New Subdomains/Hosts ({len(self.new_hosts)}):")
            for h in sorted(self.new_hosts):
                lines.append(f"     + {h}")

        if self.removed_hosts:
            lines.append(f" [-] Decommissioned/Unresponsive Hosts ({len(self.removed_hosts)}):")
            for h in sorted(self.removed_hosts):
                lines.append(f"     - {h}")

        if self.new_ports:
            lines.append(" [+] Newly Opened Ports:")
            for host, ports in sorted(self.new_ports.items()):
                for p in ports:
                    lines.append(f"     + {host}:{p}")

        if self.closed_ports:
            lines.append(" [-] Closed Ports:")
            for host, ports in sorted(self.closed_ports.items()):
                for p in ports:
                    lines.append(f"     - {host}:{p}")

        if self.new_findings:
            lines.append(f" [!] New Security Findings ({len(self.new_findings)}):")
            for f in self.new_findings:
                sev = f.get("severity", "info").upper()
                lines.append(f"     + [{sev}] {f.get('title')} ({f.get('target')})")

        if self.resolved_findings:
            lines.append(f" [v] Resolved Vulnerabilities ({len(self.resolved_findings)}):")
            for f in self.resolved_findings:
                lines.append(f"     - {f.get('title')} ({f.get('target')})")

        if self.status_changes:
            lines.append(" [*] Web Service Status Code Shifts:")
            for sc in self.status_changes:
                lines.append(f"     * {sc.get('url')}: {sc.get('old_status')} -> {sc.get('new_status')}")

        lines.append("=" * 60)
        return "\n".join(lines)


class StateDatabase:
    """Manages SQLite storage for historical scan results."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(".", DEFAULT_DB_FILENAME)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create necessary schema if it does not already exist."""
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    duration_seconds REAL,
                    total_hosts INTEGER,
                    total_open_ports INTEGER,
                    total_findings INTEGER,
                    raw_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, start_time DESC)
            """)
            conn.commit()

    def save_scan(self, result: ScanResult) -> None:
        """Store a scan snapshot into SQLite."""
        data = result.to_dict()
        summary = data.get("summary", {})
        raw_json = json.dumps(data)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans (
                    scan_id, target, start_time, end_time,
                    duration_seconds, total_hosts, total_open_ports,
                    total_findings, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.target,
                    result.start_time.isoformat(),
                    result.end_time.isoformat() if result.end_time else None,
                    result.duration_seconds() or 0.0,
                    summary.get("total_hosts", len(result.hosts)),
                    summary.get("total_open_ports", 0),
                    summary.get("total_findings", len(result.findings)),
                    raw_json,
                ),
            )
            conn.commit()
        logger.debug(f"Saved scan {result.scan_id} to database {self.db_path}")

    def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a specific scan by scan_id."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT raw_json FROM scans WHERE scan_id = ?", (scan_id,))
            row = cur.fetchone()
            if row:
                return json.loads(row["raw_json"])
        return None

    def get_latest_scans_for_target(self, target: str, limit: int = 2) -> list[dict[str, Any]]:
        """Fetch the most recent N scans for a given target."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT raw_json FROM scans WHERE target = ? ORDER BY start_time DESC LIMIT ?",
                (target, limit),
            )
            rows = cur.fetchall()
            return [json.loads(r["raw_json"]) for r in rows]

    def list_all_scans(self) -> list[dict[str, Any]]:
        """List summary metadata of all stored scans."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT scan_id, target, start_time, duration_seconds, total_hosts, total_open_ports, total_findings FROM scans ORDER BY start_time DESC"
            )
            return [dict(r) for r in cur.fetchall()]


class DiffEngine:
    """Computes asset deltas between two scans."""

    @staticmethod
    def compute(prev_data: Optional[dict[str, Any]], curr_data: dict[str, Any]) -> ScanDelta:
        target = curr_data.get("target", "unknown")
        curr_id = curr_data.get("scan_id", "current")

        if not prev_data:
            # Baseline scan: everything in curr_data is brand new
            curr_hosts = list(curr_data.get("hosts", {}).keys())
            return ScanDelta(
                target=target,
                prev_scan_id=None,
                curr_scan_id=curr_id,
                new_hosts=curr_hosts,
                new_findings=curr_data.get("findings", []),
            )

        prev_id = prev_data.get("scan_id", "previous")
        prev_hosts_map = prev_data.get("hosts", {})
        curr_hosts_map = curr_data.get("hosts", {})

        prev_hosts = set(prev_hosts_map.keys())
        curr_hosts = set(curr_hosts_map.keys())

        new_hosts = sorted(list(curr_hosts - prev_hosts))
        removed_hosts = sorted(list(prev_hosts - curr_hosts))

        # Check port changes on shared hosts
        new_ports: dict[str, list[int]] = {}
        closed_ports: dict[str, list[int]] = {}

        for host in curr_hosts & prev_hosts:
            p_ports = {p.get("port") for p in prev_hosts_map[host].get("open_ports", []) if "port" in p}
            c_ports = {p.get("port") for p in curr_hosts_map[host].get("open_ports", []) if "port" in p}

            opened = sorted(list(c_ports - p_ports))
            closed = sorted(list(p_ports - c_ports))

            if opened:
                new_ports[host] = opened
            if closed:
                closed_ports[host] = closed

        # Check status code shifts
        status_changes = []
        for host in curr_hosts & prev_hosts:
            p_http = {s.get("url"): s.get("status_code") for s in prev_hosts_map[host].get("http_services", [])}
            c_http = {s.get("url"): s.get("status_code") for s in curr_hosts_map[host].get("http_services", [])}

            for url, c_code in c_http.items():
                if url in p_http and p_http[url] != c_code:
                    status_changes.append({
                        "url": url,
                        "old_status": p_http[url],
                        "new_status": c_code,
                    })

        # Findings diff (match on title + target)
        def finding_key(f: dict[str, Any]) -> str:
            return f"{f.get('target', '')}|{f.get('title', '')}"

        prev_find_map = {finding_key(f): f for f in prev_data.get("findings", [])}
        curr_find_map = {finding_key(f): f for f in curr_data.get("findings", [])}

        new_findings = [f for k, f in curr_find_map.items() if k not in prev_find_map]
        resolved_findings = [f for k, f in prev_find_map.items() if k not in curr_find_map]

        return ScanDelta(
            target=target,
            prev_scan_id=prev_id,
            curr_scan_id=curr_id,
            new_hosts=new_hosts,
            removed_hosts=removed_hosts,
            new_ports=new_ports,
            closed_ports=closed_ports,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            status_changes=status_changes,
        )
