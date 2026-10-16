"""
Tests for ReconForge reporting subsystem.
Verifies JSON serialization, HTML generation (Jinja2 & fallback),
and re-rendering from results.json.
"""
import json
import os
import tempfile
from datetime import datetime, timezone
import pytest

from reconforge.core.models import (
    ScanResult, HostResult, PortInfo, HTTPInfo, Finding, Severity, Target, TargetType
)
from reconforge.reporting.json_report import JSONReporter
from reconforge.reporting.html_report import HTMLReporter


@pytest.fixture
def sample_scan_result() -> ScanResult:
    result = ScanResult(
        target="example.com",
        scan_id="test1234",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        metadata={"tool": "reconforge", "version": "1.0.0", "operator": "tester"},
        modules_run=["dns_enum", "portscan", "http_probe"],
    )
    result.hosts["example.com"] = HostResult(
        hostname="example.com",
        ip_addresses=["93.184.216.34"],
        open_ports=[
            PortInfo(port=80, service="http", banner="Apache/2.4.41"),
            PortInfo(port=443, service="https", banner="Apache/2.4.41"),
        ],
        http_services=[
            HTTPInfo(url="https://example.com", status_code=200, title="Example Domain", server="ECS (ord/4CC4)"),
        ],
        technologies=["Apache HTTP Server"],
    )
    result.findings.append(Finding(
        id="dns-missing-dmarc",
        title="Missing DMARC Record",
        severity=Severity.MEDIUM,
        description="No DMARC record found for example.com",
        target="example.com",
        module="dns_enum",
        recommendation="Add a DMARC TXT record at _dmarc.example.com",
        cwe="CWE-290",
    ))
    return result


def test_json_report_generation(sample_scan_result):
    reporter = JSONReporter(sample_scan_result)
    output = reporter.generate()
    data = json.loads(output)

    assert data["target"] == "example.com"
    assert data["scan_id"] == "test1234"
    assert len(data["findings"]) == 1
    assert data["summary"]["total_hosts"] == 1
    assert data["summary"]["total_open_ports"] == 2
    assert data["summary"]["findings_by_severity"]["medium"] == 1


def test_json_report_file_write(sample_scan_result):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "report.json")
        reporter = JSONReporter(sample_scan_result)
        reporter.write(path)
        assert os.path.isfile(path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["target"] == "example.com"


def test_html_report_generation(sample_scan_result):
    reporter = HTMLReporter(sample_scan_result)
    html_output = reporter.generate()

    assert "<!DOCTYPE html>" in html_output
    assert "example.com" in html_output
    assert "Missing DMARC Record" in html_output
    assert "Apache HTTP Server" in html_output


def test_html_report_rerender_from_json(sample_scan_result):
    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "results.json")
        html_path = os.path.join(tmpdir, "results.html")

        # Save JSON
        JSONReporter(sample_scan_result).write(json_path)

        # Re-render HTML from JSON
        reporter = HTMLReporter.from_json_file(json_path)
        reporter.write(html_path)

        assert os.path.isfile(html_path)
        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "example.com" in content
        assert "Missing DMARC Record" in content
