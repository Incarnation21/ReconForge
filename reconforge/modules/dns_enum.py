"""
DNS Enumeration Module.
Queries multiple DNS record types, attempts AXFR zone transfer,
and checks SPF/DMARC email security configurations.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Optional

try:
    import dns.asyncresolver
    import dns.exception
    import dns.query
    import dns.resolver
    import dns.zone
    import dns.rdatatype
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from reconforge.core.models import DNSRecord, Finding, Severity
from reconforge.core.module import BaseModule, ModuleResult, register_module
from reconforge.core.context import ScanContext

logger = logging.getLogger(__name__)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]


@register_module
class DNSEnumModule(BaseModule):
    NAME = "dns_enum"
    DESCRIPTION = "Enumerate DNS records, attempt zone transfer, check SPF/DMARC"
    REQUIRES: set[str] = set()
    PROVIDES = {"dns_records", "nameservers", "zone_transfer"}

    def __init__(self, ctx: ScanContext):
        super().__init__(ctx)
        self.domain: Optional[str] = None

    async def run(self) -> ModuleResult:
        if not DNS_AVAILABLE:
            return ModuleResult(module_name=self.NAME, success=False, errors=["dnspython not installed"])

        target = self.ctx.target
        if target.domain:
            self.domain = target.domain
        elif target.ip:
            self.domain = target.ip
        else:
            return ModuleResult(module_name=self.NAME, success=False, errors=["No domain target"])

        host = await self.ctx.store.get_or_create_host(self.domain)
        all_records: list[DNSRecord] = []
        errors: list[str] = []

        # Query each record type
        tasks = [self._query_record_type(rtype) for rtype in RECORD_TYPES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for rtype, result in zip(RECORD_TYPES, results):
            if isinstance(result, Exception):
                errors.append(f"{rtype}: {result}")
            elif result:
                all_records.extend(result)

        # Collect nameservers for AXFR
        nameservers = [r.value for r in all_records if r.record_type == "NS"]
        self.ctx.set("nameservers", nameservers)

        # Attempt zone transfer
        axfr_records = await self._attempt_axfr(nameservers)
        if axfr_records:
            all_records.extend(axfr_records)
            await self._add_axfr_finding()

        # Check SPF / DMARC
        await self._check_email_security(all_records)

        # Save to store
        await self.ctx.store.update_host(
            self.domain,
            dns_records=all_records,
        )
        self.ctx.set("dns_records", all_records)

        return ModuleResult(
            module_name=self.NAME,
            success=True,
            data={"record_count": len(all_records), "nameservers": nameservers},
            errors=errors,
        )

    async def _query_record_type(self, rtype: str) -> list[DNSRecord]:
        records = []
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = self.ctx.config.timeout
            resolver.lifetime = self.ctx.config.timeout * 2
            answers = await resolver.resolve(self.domain, rtype)
            for rdata in answers:
                records.append(DNSRecord(
                    record_type=rtype,
                    value=rdata.to_text(),
                    ttl=answers.ttl,
                ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException as e:
            logger.debug(f"DNS query {rtype} for {self.domain}: {e}")
        except Exception as e:
            logger.debug(f"DNS {rtype} unexpected error: {e}")
        return records

    async def _attempt_axfr(self, nameservers: list[str]) -> list[DNSRecord]:
        """Attempt DNS zone transfer (AXFR) against all nameservers."""
        records = []
        for ns in nameservers[:3]:  # Limit attempts
            ns_clean = ns.rstrip(".")
            try:
                # Resolve NS to IP
                resolver = dns.asyncresolver.Resolver()
                ans = await resolver.resolve(ns_clean, "A")
                ns_ip = ans[0].address

                # Attempt AXFR in executor (synchronous dns.query)
                def do_axfr():
                    try:
                        z = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=5))
                        axfr_recs = []
                        for name, node in z.nodes.items():
                            for rdataset in node.rdatasets:
                                for rdata in rdataset:
                                    axfr_recs.append(DNSRecord(
                                        record_type=dns.rdatatype.to_text(rdataset.rdtype),
                                        value=f"{name}.{self.domain} {rdata.to_text()}",
                                    ))
                        return axfr_recs
                    except Exception:
                        return []

                result = await self.ctx.run_in_executor(do_axfr)
                if result:
                    self.logger.warning(f"AXFR SUCCESSFUL on {ns_clean}! Zone transfer exposed {len(result)} records.")
                    records.extend(result)
                    break
            except Exception as e:
                logger.debug(f"AXFR attempt failed for {ns_clean}: {e}")
        return records

    async def _add_axfr_finding(self) -> None:
        finding = Finding(
            id=self._make_finding_id(f"axfr-{self.domain}"),
            title="DNS Zone Transfer (AXFR) Allowed",
            severity=Severity.HIGH,
            description=(
                f"The DNS server for {self.domain} allows unauthenticated zone transfers (AXFR). "
                "This exposes the complete DNS zone data including internal hostnames, mail servers, "
                "and potentially internal IP addresses to any external party."
            ),
            target=self.domain,
            module=self.NAME,
            evidence=f"Successful AXFR response from nameserver of {self.domain}",
            recommendation=(
                "Restrict zone transfers to authorized secondary DNS servers only. "
                "Configure ACLs on your DNS server to prevent unauthorized AXFR requests."
            ),
            cwe="CWE-200",
        )
        await self.ctx.store.add_finding(finding)

    async def _check_email_security(self, records: list[DNSRecord]) -> None:
        """Check for missing or misconfigured SPF and DMARC records."""
        txt_values = [r.value for r in records if r.record_type == "TXT"]

        # SPF check
        spf_records = [v for v in txt_values if "v=spf1" in v.lower()]
        if not spf_records:
            await self.ctx.store.add_finding(Finding(
                id=self._make_finding_id(f"spf-missing-{self.domain}"),
                title="Missing SPF Record",
                severity=Severity.MEDIUM,
                description=f"No SPF TXT record found for {self.domain}. This allows email spoofing.",
                target=self.domain or "",
                module=self.NAME,
                recommendation="Add a TXT record: \"v=spf1 include:_spf.yourmailprovider.com ~all\"",
                cwe="CWE-290",
            ))
        elif any("+all" in s for s in spf_records):
            await self.ctx.store.add_finding(Finding(
                id=self._make_finding_id(f"spf-permissive-{self.domain}"),
                title="Permissive SPF Record (+all)",
                severity=Severity.HIGH,
                description=f"SPF record for {self.domain} uses +all, allowing any server to send email.",
                target=self.domain or "",
                module=self.NAME,
                evidence=str(spf_records),
                recommendation="Replace +all with ~all (softfail) or -all (hardfail).",
                cwe="CWE-290",
            ))

        # DMARC check
        try:
            resolver = dns.asyncresolver.Resolver()
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = await resolver.resolve(dmarc_domain, "TXT")
            dmarc_values = [r.to_text() for r in answers]
            if any("p=none" in v for v in dmarc_values):
                await self.ctx.store.add_finding(Finding(
                    id=self._make_finding_id(f"dmarc-none-{self.domain}"),
                    title="DMARC Policy Set to None (No Enforcement)",
                    severity=Severity.MEDIUM,
                    description=f"DMARC record for {self.domain} uses p=none, providing no email protection.",
                    target=self.domain or "",
                    module=self.NAME,
                    evidence=str(dmarc_values),
                    recommendation="Set DMARC policy to p=quarantine or p=reject.",
                    cwe="CWE-290",
                ))
        except Exception:
            # No DMARC record
            await self.ctx.store.add_finding(Finding(
                id=self._make_finding_id(f"dmarc-missing-{self.domain}"),
                title="Missing DMARC Record",
                severity=Severity.MEDIUM,
                description=f"No DMARC record found for {self.domain}.",
                target=self.domain or "",
                module=self.NAME,
                recommendation="Add a DMARC TXT record at _dmarc.{domain}.",
                cwe="CWE-290",
            ))
