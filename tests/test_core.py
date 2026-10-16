"""
Tests for ReconForge core modules.
Run with: pytest tests/ -v
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from reconforge.core.models import (
    Target, TargetType, Finding, Severity, ScanResult, HostResult, PortInfo
)
from reconforge.core.scope import normalize_target, ScopeValidator, ScopeViolationError
from reconforge.core.store import ResultStore
from reconforge.core.limiter import TokenBucket, RateLimiter
from reconforge.core.context import ScanConfig, ScanContext


# ─── Target Normalization Tests ───────────────────────────────────────────────

def test_normalize_domain():
    t = normalize_target("example.com")
    assert t.type == TargetType.DOMAIN
    assert t.domain == "example.com"


def test_normalize_ip():
    t = normalize_target("1.2.3.4")
    assert t.type == TargetType.IP
    assert t.ip == "1.2.3.4"


def test_normalize_cidr():
    t = normalize_target("10.0.0.0/24")
    assert t.type == TargetType.CIDR
    assert t.cidr is not None


def test_normalize_url():
    t = normalize_target("https://example.com")
    assert t.type == TargetType.URL
    assert t.domain == "example.com"
    assert t.scheme == "https"


def test_normalize_url_with_port():
    t = normalize_target("http://example.com:8080")
    assert t.type == TargetType.URL
    assert t.port == 8080


# ─── Scope Validator Tests ────────────────────────────────────────────────────

def test_scope_private_ip_blocked():
    validator = ScopeValidator()
    with pytest.raises(ScopeViolationError):
        validator.validate("192.168.1.1")


def test_scope_private_ip_allowed_with_flag():
    validator = ScopeValidator(allow_private=True)
    # Should not raise
    validator.validate("192.168.1.1")


def test_scope_domain_in_scope():
    validator = ScopeValidator(allowed_domains=["example.com"])
    assert validator.is_in_scope("example.com")
    assert validator.is_in_scope("sub.example.com")
    assert not validator.is_in_scope("other.com")


def test_scope_cidr_in_scope():
    validator = ScopeValidator(allowed_cidrs=["203.0.113.0/24"])
    assert validator.is_in_scope("203.0.113.50")
    assert not validator.is_in_scope("203.0.114.1")


def test_scope_no_restrictions_allows_all():
    validator = ScopeValidator()
    # Public IPs with no restrictions should be allowed
    assert validator.is_in_scope("8.8.8.8")


# ─── ResultStore Tests ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_result_store_create_host():
    result = ScanResult(target="test.com", scan_id="abc123")
    store = ResultStore(result)

    host = await store.get_or_create_host("test.com")
    assert host.hostname == "test.com"
    assert "test.com" in result.hosts


@pytest.mark.asyncio
async def test_result_store_deduplicate_findings():
    result = ScanResult(target="test.com", scan_id="abc123")
    store = ResultStore(result)

    finding = Finding(
        id="test-finding-1",
        title="Test Finding",
        severity=Severity.HIGH,
        description="Test",
        target="test.com",
        module="test",
    )

    await store.add_finding(finding)
    await store.add_finding(finding)  # Duplicate

    assert len(result.findings) == 1


@pytest.mark.asyncio
async def test_result_store_update_host_merge_lists():
    result = ScanResult(target="test.com", scan_id="abc123")
    store = ResultStore(result)
    await store.get_or_create_host("test.com")

    await store.update_host("test.com", ip_addresses=["1.1.1.1"])
    await store.update_host("test.com", ip_addresses=["2.2.2.2"])

    host = store.get_host("test.com")
    assert "1.1.1.1" in host.ip_addresses
    assert "2.2.2.2" in host.ip_addresses


# ─── Token Bucket Tests ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_token_bucket_acquire():
    bucket = TokenBucket(rate=100.0, capacity=10.0)
    # Should be able to acquire immediately when full
    await asyncio.wait_for(bucket.acquire(1.0), timeout=1.0)


@pytest.mark.asyncio
async def test_rate_limiter_module_semaphore():
    limiter = RateLimiter(global_rate=1000.0, global_concurrency=100)
    sem = limiter.get_module_sem("portscan")
    assert sem._value == 500  # Port scan cap

    sem2 = limiter.get_module_sem("dir_enum")
    assert sem2._value == 30


# ─── Model Serialization Tests ────────────────────────────────────────────────

def test_scan_result_to_dict():
    result = ScanResult(target="test.com", scan_id="abc123")
    result.end_time = datetime.now(timezone.utc)
    result.hosts["test.com"] = HostResult(
        hostname="test.com",
        ip_addresses=["1.2.3.4"],
        open_ports=[PortInfo(port=80, service="http")],
    )
    result.findings.append(Finding(
        id="f1",
        title="Test",
        severity=Severity.HIGH,
        description="desc",
        target="test.com",
        module="test",
    ))

    d = result.to_dict()
    assert d["target"] == "test.com"
    assert d["summary"]["total_hosts"] == 1
    assert d["summary"]["total_open_ports"] == 1
    assert d["summary"]["findings_by_severity"]["high"] == 1


def test_finding_to_dict():
    f = Finding(
        id="test-001",
        title="SQL Injection",
        severity=Severity.CRITICAL,
        description="SQLi found",
        target="example.com",
        module="custom",
        cwe="CWE-89",
    )
    d = f.to_dict()
    assert d["severity"] == "critical"
    assert d["cwe"] == "CWE-89"


# ─── CLI Integration Smoke Test ───────────────────────────────────────────────

def test_normalize_target_subdomain():
    t = normalize_target("mail.example.com")
    assert t.type == TargetType.DOMAIN
    assert t.domain == "mail.example.com"


def test_normalize_ipv6():
    t = normalize_target("::1")
    assert t.type == TargetType.IP


def test_scope_validator_load_from_list():
    v = ScopeValidator(
        allowed_domains=["target.com", "other.org"],
        allowed_cidrs=["198.51.100.0/24"],
    )
    assert v.is_in_scope("api.target.com")
    assert v.is_in_scope("198.51.100.42")
    assert not v.is_in_scope("attacker.com")
