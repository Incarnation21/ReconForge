"""
Tests for Continuous Monitoring and State Diff Engine.
Verifies SQLite schema creation, scan storage, delta computation,
and terminal diff formatting.
"""
import os
import tempfile
import pytest

from reconforge.core.diff_engine import DiffEngine, ScanDelta, StateDatabase
from reconforge.core.models import Finding, HostResult, PortInfo, ScanResult, Severity


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_reconforge.db"
    return str(db_file)


def test_state_database_save_and_retrieve(temp_db):
    db = StateDatabase(temp_db)

    # Create dummy scan
    res1 = ScanResult(target="target.com", scan_id="scan1")
    host1 = HostResult(hostname="api.target.com", ip_addresses=["1.1.1.1"])
    host1.open_ports.append(PortInfo(port=443, service="https"))
    res1.hosts["api.target.com"] = host1
    res1.findings.append(
        Finding(
            id="F1",
            title="Missing HSTS",
            severity=Severity.LOW,
            description="No HSTS",
            target="api.target.com",
            module="http_probe",
        )
    )

    db.save_scan(res1)

    # Retrieve
    retrieved = db.get_scan("scan1")
    assert retrieved is not None
    assert retrieved["scan_id"] == "scan1"
    assert retrieved["target"] == "target.com"
    assert "api.target.com" in retrieved["hosts"]

    # List scans
    scans = db.list_all_scans()
    assert len(scans) == 1
    assert scans[0]["scan_id"] == "scan1"


def test_diff_engine_baseline():
    """When no previous scan exists, all current assets are flagged as new."""
    curr = {
        "target": "example.com",
        "scan_id": "scan_curr",
        "hosts": {
            "app.example.com": {"open_ports": [{"port": 80}]},
            "api.example.com": {"open_ports": [{"port": 443}]},
        },
        "findings": [
            {"id": "F1", "title": "Open Port", "severity": "info", "target": "app.example.com"}
        ],
    }

    delta = DiffEngine.compute(None, curr)
    assert delta.has_changes() is True
    assert set(delta.new_hosts) == {"app.example.com", "api.example.com"}
    assert delta.removed_hosts == []
    assert len(delta.new_findings) == 1


def test_diff_engine_delta_computation():
    """Verify detection of new subdomains, removed subdomains, port changes, and new findings."""
    prev = {
        "target": "example.com",
        "scan_id": "scan_prev",
        "hosts": {
            "api.example.com": {"open_ports": [{"port": 80}]},
            "old-portal.example.com": {"open_ports": [{"port": 8080}]},
        },
        "findings": [
            {"id": "F1", "title": "Old Finding", "severity": "low", "target": "api.example.com"}
        ],
    }

    curr = {
        "target": "example.com",
        "scan_id": "scan_curr",
        "hosts": {
            "api.example.com": {"open_ports": [{"port": 80}, {"port": 443}]},  # 443 newly opened
            "staging.example.com": {"open_ports": [{"port": 8443}]},           # new host
            # old-portal.example.com removed
        },
        "findings": [
            {"id": "F2", "title": "Verified Takeover", "severity": "critical", "target": "staging.example.com"}
        ],
    }

    delta = DiffEngine.compute(prev, curr)
    assert delta.has_changes() is True

    # Host changes
    assert delta.new_hosts == ["staging.example.com"]
    assert delta.removed_hosts == ["old-portal.example.com"]

    # Port changes on api.example.com
    assert delta.new_ports == {"api.example.com": [443]}
    assert delta.closed_ports == {}

    # Finding changes
    assert len(delta.new_findings) == 1
    assert delta.new_findings[0]["title"] == "Verified Takeover"
    assert len(delta.resolved_findings) == 1
    assert delta.resolved_findings[0]["title"] == "Old Finding"

    # Terminal output
    summary = delta.to_summary_text()
    assert "+ staging.example.com" in summary
    assert "- old-portal.example.com" in summary
    assert "+ api.example.com:443" in summary
    assert "[CRITICAL] Verified Takeover" in summary
