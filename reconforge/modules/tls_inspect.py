"""
TLS/SSL Inspection Module.
Parses X.509 certificates, checks expiry, inspects protocols and ciphers.
Feeds discovered SAN hostnames back to the orchestrator.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from reconforge.core.models import Finding, Severity, TLSInfo
from reconforge.core.module import BaseModule, ModuleResult, register_module
from reconforge.core.context import ScanContext

logger = logging.getLogger(__name__)

LEGACY_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
WEAK_CIPHERS = {"RC4", "3DES", "DES", "MD5", "EXPORT", "NULL", "ANON"}


@register_module
class TLSInspectModule(BaseModule):
    NAME = "tls_inspect"
    DESCRIPTION = "X.509 certificate parsing, protocol audit, cipher inspection, SAN extraction"
    REQUIRES = {"http_services"}
    PROVIDES = {"tls_info"}

    async def run(self) -> ModuleResult:
        hosts = self.ctx.store.get_all_hosts()
        inspected = 0
        sem = asyncio.Semaphore(30)

        for hostname in hosts:
            host = self.ctx.store.get_host(hostname)
            if not host:
                continue

            # Look for HTTPS services
            https_urls = [
                s.url for s in host.http_services
                if s.url.startswith("https://")
            ]
            # Also try port 443 even if not probed yet
            if not https_urls:
                https_urls = [f"https://{hostname}"]

            for url in https_urls[:1]:  # Inspect first HTTPS endpoint
                parsed = url.split("://", 1)[1].split("/")[0]
                port_part = parsed.split(":")
                host_str = port_part[0]
                port = int(port_part[1]) if len(port_part) > 1 else 443

                tls_info = await self._inspect_tls(host_str, port, hostname, sem)
                if tls_info:
                    inspected += 1
                    await self.ctx.store.update_host(hostname, tls_info=tls_info)
                    await self._generate_findings(hostname, tls_info)

        return ModuleResult(
            module_name=self.NAME,
            success=True,
            data={"hosts_inspected": inspected},
        )

    async def _inspect_tls(self, hostname: str, port: int, original_host: str, sem: asyncio.Semaphore) -> Optional[TLSInfo]:
        async with sem:
            try:
                result = await self.ctx.run_in_executor(
                    self._sync_tls_inspect, hostname, port
                )
                return result
            except Exception as e:
                self.logger.debug(f"TLS inspect failed for {hostname}:{port}: {e}")
                return None

    def _sync_tls_inspect(self, hostname: str, port: int) -> Optional[TLSInfo]:
        """Synchronous TLS inspection (runs in thread pool)."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    negotiated_protocol = ssock.version() or ""
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else ""

                    tls_info = TLSInfo(
                        protocols=[negotiated_protocol] if negotiated_protocol else [],
                        ciphers=[cipher_name] if cipher_name else [],
                    )

                    if der_cert and CRYPTO_AVAILABLE:
                        self._parse_certificate(der_cert, tls_info)

                    return tls_info
        except Exception as e:
            logger.debug(f"TLS sync inspect error: {e}")
            return None

    def _parse_certificate(self, der_cert: bytes, tls_info: TLSInfo) -> None:
        """Parse X.509 certificate using cryptography library."""
        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # Subject
        subject = {attr.oid._name: attr.value for attr in cert.subject}
        tls_info.subject = subject

        # Issuer
        issuer = {attr.oid._name: attr.value for attr in cert.issuer}
        tls_info.issuer = issuer

        # Serial
        tls_info.serial_number = format(cert.serial_number, "x")

        # Signature algorithm
        tls_info.signature_algorithm = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""

        # Validity
        now = datetime.now(timezone.utc)
        tls_info.not_before = cert.not_valid_before_utc
        tls_info.not_after = cert.not_valid_after_utc
        tls_info.is_expired = now > cert.not_valid_after_utc
        delta = cert.not_valid_after_utc - now
        tls_info.days_until_expiry = delta.days if not tls_info.is_expired else -abs(delta.days)

        # Self-signed check
        tls_info.is_self_signed = cert.subject == cert.issuer

        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            tls_info.san = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            # Fallback to CN
            cn = subject.get("commonName", "")
            if cn:
                tls_info.san = [cn]

    async def _generate_findings(self, hostname: str, tls: TLSInfo) -> None:
        if tls.is_expired:
            await self.ctx.store.add_finding(Finding(
                id=self._make_finding_id(f"{hostname}-cert-expired"),
                title="SSL/TLS Certificate Expired",
                severity=Severity.HIGH,
                description=f"The TLS certificate for {hostname} expired on {tls.not_after}.",
                target=hostname,
                module=self.NAME,
                evidence=f"Not After: {tls.not_after}",
                recommendation="Renew the TLS certificate immediately.",
                cwe="CWE-295",
            ))
        elif tls.days_until_expiry is not None and tls.days_until_expiry < 30:
            await self.ctx.store.add_finding(Finding(
                id=self._make_finding_id(f"{hostname}-cert-expiring"),
                title="TLS Certificate Expiring Soon",
                severity=Severity.MEDIUM,
                description=f"Certificate for {hostname} expires in {tls.days_until_expiry} days.",
                target=hostname,
                module=self.NAME,
                recommendation="Renew the TLS certificate before expiry.",
                cwe="CWE-295",
            ))

        if tls.is_self_signed:
            await self.ctx.store.add_finding(Finding(
                id=self._make_finding_id(f"{hostname}-self-signed"),
                title="Self-Signed TLS Certificate",
                severity=Severity.MEDIUM,
                description=f"The certificate for {hostname} is self-signed, which is not trusted by browsers.",
                target=hostname,
                module=self.NAME,
                recommendation="Replace with a certificate from a trusted CA (e.g., Let's Encrypt).",
                cwe="CWE-295",
            ))

        for proto in tls.protocols:
            if proto in LEGACY_PROTOCOLS:
                await self.ctx.store.add_finding(Finding(
                    id=self._make_finding_id(f"{hostname}-legacy-proto-{proto}"),
                    title=f"Legacy TLS Protocol Enabled: {proto}",
                    severity=Severity.HIGH,
                    description=f"{hostname} supports {proto}, which is deprecated and insecure.",
                    target=hostname,
                    module=self.NAME,
                    evidence=f"Negotiated protocol: {proto}",
                    recommendation=f"Disable {proto} and use TLS 1.2 or TLS 1.3 only.",
                    cwe="CWE-327",
                ))

        for cipher in tls.ciphers:
            for weak in WEAK_CIPHERS:
                if weak.upper() in cipher.upper():
                    await self.ctx.store.add_finding(Finding(
                        id=self._make_finding_id(f"{hostname}-weak-cipher-{cipher[:20]}"),
                        title=f"Weak Cipher Suite: {cipher}",
                        severity=Severity.MEDIUM,
                        description=f"The cipher suite '{cipher}' is cryptographically weak.",
                        target=hostname,
                        module=self.NAME,
                        evidence=f"Cipher: {cipher}",
                        recommendation="Configure your server to use strong cipher suites only (AES-GCM, ChaCha20).",
                        cwe="CWE-327",
                    ))
                    break
