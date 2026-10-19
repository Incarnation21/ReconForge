"""
Tests for Subdomain Takeover Detection Module.
Verifies CNAME analysis, third-party provider fingerprint matching,
and finding generation.
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from reconforge.core.context import ScanConfig, ScanContext
from reconforge.core.models import (
    DNSRecord,
    Finding,
    HostResult,
    ScanResult,
    Severity,
    Target,
    TargetType,
)
from reconforge.modules.takeover import TakeoverModule, TAKEOVER_SIGNATURES


@pytest.fixture
def test_context():
    target = Target(raw="example.com", type=TargetType.DOMAIN, domain="example.com")
    config = ScanConfig(authorized=True)
    scan_result = ScanResult(target="example.com", scan_id="test_takeover")
    return ScanContext(target=target, config=config, scan_result=scan_result)


@pytest.mark.asyncio
async def test_takeover_s3_verified(test_context):
    """Test detecting an unclaimed Amazon S3 bucket via CNAME and fingerprint."""
    module = TakeoverModule(test_context)

    # Setup host with S3 CNAME
    host = await test_context.store.get_or_create_host("assets.example.com")
    host.dns_records.append(
        DNSRecord(record_type="CNAME", value="assets-unclaimed.s3.amazonaws.com")
    )

    # Mock _check_cname_nxdomain and _verify_takeover
    with patch.object(module, "_check_cname_nxdomain", AsyncMock(return_value=False)), \
         patch.object(
             module,
             "_verify_takeover",
             AsyncMock(return_value=(True, "The specified bucket does not exist", 404)),
         ):
        result = await module.run()

    assert result.success is True
    assert result.data["takeovers_found"] == 1

    findings = test_context.store.result.findings
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.CRITICAL
    assert "Amazon S3" in finding.title
    assert "assets.example.com" in finding.title
    assert finding.cvss == 8.6
    assert "CWE-284" in (finding.cwe or "")


@pytest.mark.asyncio
async def test_takeover_github_pages_verified(test_context):
    """Test detecting an unclaimed GitHub Pages site."""
    module = TakeoverModule(test_context)

    host = await test_context.store.get_or_create_host("docs.example.com")
    host.dns_records.append(
        DNSRecord(record_type="CNAME", value="example-docs.github.io")
    )

    with patch.object(module, "_check_cname_nxdomain", AsyncMock(return_value=False)), \
         patch.object(
             module,
             "_verify_takeover",
             AsyncMock(return_value=(True, "There isn't a GitHub Pages site here", 404)),
         ):
        result = await module.run()

    assert result.success is True
    assert result.data["takeovers_found"] == 1
    finding = test_context.store.result.findings[0]
    assert finding.severity == Severity.CRITICAL
    assert "GitHub Pages" in finding.title


@pytest.mark.asyncio
async def test_takeover_dangling_cname_nxdomain(test_context):
    """Test detecting a dangling CNAME where target returns NXDOMAIN."""
    module = TakeoverModule(test_context)

    host = await test_context.store.get_or_create_host("legacy.example.com")
    host.dns_records.append(
        DNSRecord(record_type="CNAME", value="deleted-app.herokuapp.com")
    )

    # CNAME target returns NXDOMAIN, and HTTP probe fails / doesn't match
    with patch.object(module, "_check_cname_nxdomain", AsyncMock(return_value=True)), \
         patch.object(module, "_verify_takeover", AsyncMock(return_value=(False, None, 0))):
        result = await module.run()

    assert result.success is True
    assert result.data["takeovers_found"] == 1
    finding = test_context.store.result.findings[0]
    assert finding.severity == Severity.HIGH
    assert "Dangling CNAME" in finding.title


@pytest.mark.asyncio
async def test_takeover_no_cname(test_context):
    """Test normal host without CNAME produces 0 takeover findings."""
    module = TakeoverModule(test_context)

    host = await test_context.store.get_or_create_host("app.example.com")
    host.dns_records.append(DNSRecord(record_type="A", value="93.184.216.34"))

    with patch.object(module, "_resolve_cnames", AsyncMock(return_value=[])):
        result = await module.run()

    assert result.success is True
    assert result.data["takeovers_found"] == 0
    assert len(test_context.store.result.findings) == 0
