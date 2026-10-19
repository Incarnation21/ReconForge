"""
Subdomain Takeover Detection Module.
Identifies dangling CNAME records pointing to unclaimed third-party cloud services
(AWS S3, GitHub Pages, Heroku, Azure, Shopify, Fastly, etc.) and verifies potential
takeovers against known provider fingerprints.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Optional

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import dns.asyncresolver
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from reconforge.core.models import Finding, Severity, DNSRecord
from reconforge.core.module import BaseModule, ModuleResult, register_module
from reconforge.core.context import ScanContext

logger = logging.getLogger(__name__)

# Canonical fingerprint database of third-party services vulnerable to takeover
TAKEOVER_SIGNATURES: list[dict[str, Any]] = [
    {
        "provider": "Amazon S3 / AWS",
        "cname_patterns": ["s3.amazonaws.com", "s3-website", "s3.dualstack", ".amazonaws.com"],
        "fingerprints": [
            "The specified bucket does not exist",
            "NoSuchBucket",
            "BucketName specifies a bucket which does not exist",
        ],
        "severity": Severity.CRITICAL,
    },
    {
        "provider": "GitHub Pages",
        "cname_patterns": ["github.io"],
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "severity": Severity.CRITICAL,
    },
    {
        "provider": "Heroku",
        "cname_patterns": ["herokuapp.com", "herokudns.com"],
        "fingerprints": [
            "No such app",
            "There's nothing here, yet.",
            "heroku-error-page",
            "<title>No such app</title>",
        ],
        "severity": Severity.CRITICAL,
    },
    {
        "provider": "Microsoft Azure",
        "cname_patterns": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net", "azureedge.net"],
        "fingerprints": [
            "404 Web Site not found",
            "The resource you are looking for has been removed",
            "503 Service Unavailable",
        ],
        "severity": Severity.CRITICAL,
    },
    {
        "provider": "Shopify",
        "cname_patterns": ["myshopify.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable",
            "To finish setting up your new web address, go to your domain settings",
        ],
        "severity": Severity.HIGH,
    },
    {
        "provider": "Ghost",
        "cname_patterns": ["ghost.io"],
        "fingerprints": [
            "The thing you were looking for is no longer here",
            "The site you are looking for is not configured",
        ],
        "severity": Severity.HIGH,
    },
    {
        "provider": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "fingerprints": [
            "project not found",
            "repository not found",
        ],
        "severity": Severity.HIGH,
    },
    {
        "provider": "Fastly",
        "cname_patterns": ["fastly.net"],
        "fingerprints": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
        "severity": Severity.HIGH,
    },
    {
        "provider": "Pantheon",
        "cname_patterns": ["pantheonsite.io"],
        "fingerprints": [
            "404 error unknown site",
            "The site you are looking for does not exist on Pantheon",
        ],
        "severity": Severity.HIGH,
    },
    {
        "provider": "Tumblr",
        "cname_patterns": ["domains.tumblr.com"],
        "fingerprints": [
            "Whatever you were looking for doesn't seem to exist at this URL",
            "There's nothing here.",
        ],
        "severity": Severity.MEDIUM,
    },
    {
        "provider": "WordPress.com",
        "cname_patterns": ["wordpress.com"],
        "fingerprints": [
            "Do you want to register",
            "is no longer available",
        ],
        "severity": Severity.MEDIUM,
    },
    {
        "provider": "Readme.io",
        "cname_patterns": ["readme.io"],
        "fingerprints": [
            "Project doesnt exist... yet!",
        ],
        "severity": Severity.HIGH,
    },
]


@register_module
class TakeoverModule(BaseModule):
    """
    Subdomain Takeover Module.
    Scans host CNAMEs for pointers to external third-party services and probes
    HTTP/HTTPS responses for unclaimed resource signatures.
    """
    NAME = "takeover"
    DESCRIPTION = "Detect dangling CNAME pointers and verified subdomain takeover vulnerabilities"
    REQUIRES = {"subdomains"}
    PROVIDES = {"takeover_findings"}

    def __init__(self, ctx: ScanContext):
        super().__init__(ctx)
        self.signatures = TAKEOVER_SIGNATURES

    async def run(self) -> ModuleResult:
        if not DNS_AVAILABLE:
            return ModuleResult(module_name=self.NAME, success=False, errors=["dnspython not available"])

        hosts = list(self.ctx.store.result.hosts.values())
        if not hosts:
            # Fall back to root target
            if self.ctx.target.domain:
                root_host = await self.ctx.store.get_or_create_host(self.ctx.target.domain)
                hosts = [root_host]
            else:
                return ModuleResult(module_name=self.NAME, success=True, data={"analyzed": 0})

        findings_count = 0
        tasks = [self._check_host(host.hostname) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, int):
                findings_count += res

        return ModuleResult(
            module_name=self.NAME,
            success=True,
            data={"hosts_checked": len(hosts), "takeovers_found": findings_count},
        )

    async def _check_host(self, hostname: str) -> int:
        """Check a single hostname for dangling CNAMEs and takeover signatures."""
        cnames = await self._resolve_cnames(hostname)
        if not cnames:
            return 0

        findings_found = 0
        for cname in cnames:
            cname_clean = cname.rstrip(".").lower()

            # Check if CNAME target itself is NXDOMAIN (dangling pointer)
            is_nxdomain = await self._check_cname_nxdomain(cname_clean)

            # Match against signatures
            matched_sig = None
            for sig in self.signatures:
                for pattern in sig["cname_patterns"]:
                    if pattern in cname_clean:
                        matched_sig = sig
                        break
                if matched_sig:
                    break

            if matched_sig:
                # Probe HTTP/HTTPS to verify takeover
                verified, fp_matched, status = await self._verify_takeover(hostname, matched_sig["fingerprints"])
                if verified:
                    finding = Finding(
                        id=f"TAKEOVER-VERIFIED-{hostname}",
                        title=f"Verified Subdomain Takeover: {hostname} -> {cname_clean} ({matched_sig['provider']})",
                        severity=matched_sig["severity"],
                        description=(
                            f"Host '{hostname}' points via CNAME to '{cname_clean}' ({matched_sig['provider']}), "
                            f"and the HTTP response contains signature '{fp_matched}'. "
                            f"The remote resource appears unclaimed or deleted, allowing an attacker to claim it "
                            f"and hijack the entire subdomain."
                        ),
                        target=hostname,
                        module=self.NAME,
                        evidence=(
                            f"CNAME: {cname_clean}\n"
                            f"Provider: {matched_sig['provider']}\n"
                            f"HTTP Status: {status}\n"
                            f"Matched Signature: {fp_matched}"
                        ),
                        recommendation=(
                            f"1. Remove or update the DNS CNAME record for '{hostname}'.\n"
                            f"2. Or re-create/claim the resource under your organization's {matched_sig['provider']} account."
                        ),
                        cwe="CWE-284: Improper Access Control",
                        cvss=8.6,
                    )
                    await self.ctx.store.add_finding(finding)
                    host = await self.ctx.store.get_or_create_host(hostname)
                    host.findings.append(finding)
                    findings_found += 1
                    logger.warning(f"[!] SUBDOMAIN TAKEOVER DETECTED on {hostname} -> {cname_clean}")
                elif is_nxdomain:
                    # Dangling CNAME to non-resolving target
                    finding = Finding(
                        id=f"DANGLING-CNAME-{hostname}",
                        title=f"Dangling CNAME to Non-Existent Target: {hostname} -> {cname_clean}",
                        severity=Severity.HIGH,
                        description=(
                            f"Host '{hostname}' has a CNAME pointing to '{cname_clean}', which does not resolve (NXDOMAIN). "
                            f"If this external domain is registered by an attacker, traffic or subdomains could be hijacked."
                        ),
                        target=hostname,
                        module=self.NAME,
                        evidence=f"CNAME: {cname_clean} (NXDOMAIN)",
                        recommendation=f"Remove the obsolete CNAME record for '{hostname}'.",
                        cwe="CWE-284: Improper Access Control",
                        cvss=7.2,
                    )
                    await self.ctx.store.add_finding(finding)
                    host = await self.ctx.store.get_or_create_host(hostname)
                    host.findings.append(finding)
                    findings_found += 1

            elif is_nxdomain:
                # Generic dangling CNAME
                finding = Finding(
                    id=f"DANGLING-CNAME-{hostname}",
                    title=f"Dangling DNS CNAME Record: {hostname} -> {cname_clean}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Host '{hostname}' points to '{cname_clean}', which returned NXDOMAIN. "
                        f"The destination domain has expired or does not exist."
                    ),
                    target=hostname,
                    module=self.NAME,
                    evidence=f"CNAME target '{cname_clean}' does not resolve.",
                    recommendation=f"Delete the dangling DNS CNAME record for '{hostname}'.",
                    cwe="CWE-284: Improper Access Control",
                    cvss=5.3,
                )
                await self.ctx.store.add_finding(finding)
                host = await self.ctx.store.get_or_create_host(hostname)
                host.findings.append(finding)
                findings_found += 1

        return findings_found

    async def _resolve_cnames(self, hostname: str) -> list[str]:
        """Fetch CNAME records for a given hostname."""
        # First check if we already have CNAMEs in store
        host = self.ctx.store.result.hosts.get(hostname)
        if host and host.dns_records:
            cnames = [r.value for r in host.dns_records if r.record_type.upper() == "CNAME"]
            if cnames:
                return cnames

        if not DNS_AVAILABLE:
            return []

        # Query DNS async
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = self.ctx.config.timeout
            ans = await resolver.resolve(hostname, "CNAME")
            cnames = [str(r.target).rstrip(".") for r in ans]
            # Record in host
            if host:
                for c in cnames:
                    host.dns_records.append(DNSRecord(record_type="CNAME", value=c))
            return cnames
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return []
        except Exception:
            return []

    async def _check_cname_nxdomain(self, cname_target: str) -> bool:
        """Check if the CNAME target returns NXDOMAIN."""
        if not DNS_AVAILABLE:
            return False
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = min(2.0, self.ctx.config.timeout)
            await resolver.resolve(cname_target, "A")
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            return False

    async def _verify_takeover(
        self, hostname: str, fingerprints: list[str]
    ) -> tuple[bool, Optional[str], int]:
        """Probe the host over HTTP/HTTPS to match takeover fingerprints."""
        if not AIOHTTP_AVAILABLE:
            return False, None, 0

        timeout = aiohttp.ClientTimeout(total=self.ctx.config.timeout)
        headers = {
            "User-Agent": self.ctx.config.user_agent,
            "Host": hostname,
        }

        # Check HTTPS then HTTP
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}"
            try:
                await self.ctx.limiter.acquire()
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, headers=headers, ssl=False, allow_redirects=True) as resp:
                        text = await resp.text(errors="replace")
                        status = resp.status
                        for fp in fingerprints:
                            if fp.lower() in text.lower():
                                return True, fp, status
            except Exception:
                continue

        return False, None, 0
