"""
Core data models for ReconForge.
All data classes use slots for memory efficiency and are fully type-annotated.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"


@dataclass
class Target:
    """Represents a scan target."""
    raw: str
    type: TargetType
    domain: Optional[str] = None
    ip: Optional[str] = None
    cidr: Optional[ipaddress.IPv4Network] = None
    url: Optional[str] = None
    port: Optional[int] = None
    scheme: str = "https"

    def __hash__(self) -> int:
        return hash(self.raw)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Target):
            return False
        return self.raw == other.raw

    def display(self) -> str:
        return self.raw


@dataclass
class PortInfo:
    """Information about an open port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    banner: Optional[str] = None
    version: Optional[str] = None


@dataclass
class DNSRecord:
    """A single DNS record."""
    record_type: str
    value: str
    ttl: Optional[int] = None


@dataclass
class TLSInfo:
    """TLS/SSL certificate and configuration information."""
    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    san: list[str] = field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial_number: str = ""
    signature_algorithm: str = ""
    protocols: list[str] = field(default_factory=list)
    ciphers: list[str] = field(default_factory=list)
    is_expired: bool = False
    is_self_signed: bool = False
    days_until_expiry: Optional[int] = None


@dataclass
class HTTPInfo:
    """HTTP probe result for a web endpoint."""
    url: str
    status_code: int = 0
    title: str = ""
    server: str = ""
    content_type: str = ""
    content_length: int = 0
    redirect_chain: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, Any] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    tls: Optional[TLSInfo] = None


@dataclass
class WHOISInfo:
    """WHOIS/RDAP data."""
    query: str
    registrar: str = ""
    registrant_org: str = ""
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: list[str] = field(default_factory=list)
    asn: Optional[str] = None
    asn_description: Optional[str] = None
    country: Optional[str] = None
    cidr: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A security finding identified during scanning."""
    id: str
    title: str
    severity: Severity
    description: str
    target: str
    module: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "target": self.target,
            "module": self.module,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class HostResult:
    """Aggregated result for a single host."""
    hostname: str
    ip_addresses: list[str] = field(default_factory=list)
    ptr_records: list[str] = field(default_factory=list)
    dns_records: list[DNSRecord] = field(default_factory=list)
    open_ports: list[PortInfo] = field(default_factory=list)
    http_services: list[HTTPInfo] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    directories: list[dict[str, Any]] = field(default_factory=list)
    tls_info: Optional[TLSInfo] = None
    whois_info: Optional[WHOISInfo] = None
    findings: list[Finding] = field(default_factory=list)
    subdomain_source: Optional[str] = None
    scan_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "ip_addresses": self.ip_addresses,
            "ptr_records": self.ptr_records,
            "dns_records": [{"type": r.record_type, "value": r.value, "ttl": r.ttl} for r in self.dns_records],
            "open_ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "banner": p.banner,
                    "version": p.version,
                }
                for p in self.open_ports
            ],
            "http_services": [
                {
                    "url": h.url,
                    "status_code": h.status_code,
                    "title": h.title,
                    "server": h.server,
                    "content_type": h.content_type,
                    "content_length": h.content_length,
                    "redirect_chain": h.redirect_chain,
                    "headers": h.headers,
                    "security_headers": h.security_headers,
                    "technologies": h.technologies,
                }
                for h in self.http_services
            ],
            "technologies": self.technologies,
            "directories": self.directories,
            "tls_info": (
                {
                    "subject": self.tls_info.subject,
                    "issuer": self.tls_info.issuer,
                    "san": self.tls_info.san,
                    "not_before": self.tls_info.not_before.isoformat() if self.tls_info.not_before else None,
                    "not_after": self.tls_info.not_after.isoformat() if self.tls_info.not_after else None,
                    "serial_number": self.tls_info.serial_number,
                    "signature_algorithm": self.tls_info.signature_algorithm,
                    "protocols": self.tls_info.protocols,
                    "ciphers": self.tls_info.ciphers,
                    "is_expired": self.tls_info.is_expired,
                    "is_self_signed": self.tls_info.is_self_signed,
                    "days_until_expiry": self.tls_info.days_until_expiry,
                }
                if self.tls_info
                else None
            ),
            "whois_info": (
                {
                    "query": self.whois_info.query,
                    "registrar": self.whois_info.registrar,
                    "registrant_org": self.whois_info.registrant_org,
                    "creation_date": self.whois_info.creation_date,
                    "expiration_date": self.whois_info.expiration_date,
                    "name_servers": self.whois_info.name_servers,
                    "asn": self.whois_info.asn,
                    "asn_description": self.whois_info.asn_description,
                    "country": self.whois_info.country,
                    "cidr": self.whois_info.cidr,
                }
                if self.whois_info
                else None
            ),
            "findings": [f.to_dict() for f in self.findings],
            "subdomain_source": self.subdomain_source,
            "scan_timestamp": self.scan_timestamp.isoformat(),
        }


@dataclass
class ScanResult:
    """Top-level scan result container."""
    target: str
    scan_id: str
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    hosts: dict[str, HostResult] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    modules_run: list[str] = field(default_factory=list)

    def duration_seconds(self) -> Optional[float]:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds(),
            "hosts": {k: v.to_dict() for k, v in self.hosts.items()},
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
            "modules_run": self.modules_run,
            "summary": {
                "total_hosts": len(self.hosts),
                "total_findings": len(self.findings),
                "findings_by_severity": {
                    sev.value: sum(1 for f in self.findings if f.severity == sev)
                    for sev in Severity
                },
                "total_open_ports": sum(len(h.open_ports) for h in self.hosts.values()),
                "total_web_services": sum(len(h.http_services) for h in self.hosts.values()),
            },
        }
