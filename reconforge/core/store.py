"""
Thread-safe, async-compatible result store for ReconForge.
All writes are serialized via asyncio.Lock; reads are non-blocking.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from .models import Finding, HostResult, ScanResult

logger = logging.getLogger(__name__)


class ResultStore:
    """Centralized, concurrency-safe storage for scan results."""

    def __init__(self, scan_result: ScanResult):
        self._result = scan_result
        self._lock = asyncio.Lock()
        self._finding_ids: set[str] = set()

    @property
    def result(self) -> ScanResult:
        return self._result

    async def get_or_create_host(self, hostname: str) -> HostResult:
        """Get existing HostResult or create a new one atomically."""
        async with self._lock:
            if hostname not in self._result.hosts:
                self._result.hosts[hostname] = HostResult(hostname=hostname)
            return self._result.hosts[hostname]

    async def update_host(self, hostname: str, **kwargs) -> None:
        """Update fields on a HostResult atomically."""
        async with self._lock:
            host = self._result.hosts.get(hostname)
            if host is None:
                host = HostResult(hostname=hostname)
                self._result.hosts[hostname] = host
            for key, value in kwargs.items():
                if hasattr(host, key):
                    attr = getattr(host, key)
                    if isinstance(attr, list) and isinstance(value, list):
                        # Merge lists, avoid duplicates for simple types
                        existing_set = set(str(x) for x in attr)
                        for item in value:
                            if str(item) not in existing_set:
                                attr.append(item)
                                existing_set.add(str(item))
                    else:
                        setattr(host, key, value)

    async def add_finding(self, finding: Finding) -> None:
        """Add a finding, deduplicating by ID."""
        async with self._lock:
            if finding.id not in self._finding_ids:
                self._finding_ids.add(finding.id)
                self._result.findings.append(finding)
                # Also add to host-level findings
                host = self._result.hosts.get(finding.target)
                if host:
                    host.findings.append(finding)

    async def add_module(self, module_name: str) -> None:
        """Record that a module was run."""
        async with self._lock:
            if module_name not in self._result.modules_run:
                self._result.modules_run.append(module_name)

    def get_all_hosts(self) -> list[str]:
        """Return list of all discovered hostnames (no lock needed for read)."""
        return list(self._result.hosts.keys())

    def get_host(self, hostname: str) -> Optional[HostResult]:
        """Get a host result by hostname."""
        return self._result.hosts.get(hostname)

    def get_findings_by_severity(self, severity: str) -> list[Finding]:
        """Return findings filtered by severity string."""
        from .models import Severity
        sev = Severity(severity)
        return [f for f in self._result.findings if f.severity == sev]

    def finding_count(self) -> dict[str, int]:
        """Return finding counts by severity."""
        from .models import Severity
        return {
            sev.value: sum(1 for f in self._result.findings if f.severity == sev)
            for sev in Severity
        }
