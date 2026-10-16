"""
IP Resolution Module.
Resolves hostnames to IP addresses (A/AAAA records),
performs reverse PTR lookups, and groups hosts by shared infrastructure.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Optional

try:
    import dns.asyncresolver
    import dns.exception
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from reconforge.core.module import BaseModule, ModuleResult, register_module
from reconforge.core.context import ScanContext

logger = logging.getLogger(__name__)


@register_module
class IPResolveModule(BaseModule):
    NAME = "ip_resolve"
    DESCRIPTION = "Resolve hostnames to IPs, perform PTR lookups, group by shared infrastructure"
    REQUIRES = {"dns_records"}
    PROVIDES = {"ip_map", "ptr_map"}

    async def run(self) -> ModuleResult:
        hosts = self.ctx.store.get_all_hosts()
        if not hosts:
            return ModuleResult(module_name=self.NAME, success=True, data={"hosts_resolved": 0})

        sem = asyncio.Semaphore(100)
        tasks = [self._resolve_host(hostname, sem) for hostname in hosts]
        await asyncio.gather(*tasks, return_exceptions=True)

        ip_map = {}
        for hostname in hosts:
            host = self.ctx.store.get_host(hostname)
            if host and host.ip_addresses:
                ip_map[hostname] = host.ip_addresses

        self.ctx.set("ip_map", ip_map)
        return ModuleResult(
            module_name=self.NAME,
            success=True,
            data={"hosts_resolved": len(ip_map)},
        )

    async def _resolve_host(self, hostname: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            ip_addresses = []
            ptr_records = []

            # Handle IP targets directly
            try:
                addr = ipaddress.ip_address(hostname)
                ip_addresses.append(str(addr))
                ptr = await self._ptr_lookup(str(addr))
                if ptr:
                    ptr_records.append(ptr)
                await self.ctx.store.update_host(
                    hostname,
                    ip_addresses=ip_addresses,
                    ptr_records=ptr_records,
                )
                return
            except ValueError:
                pass

            # DNS resolution
            if DNS_AVAILABLE:
                for qtype in ("A", "AAAA"):
                    try:
                        resolver = dns.asyncresolver.Resolver()
                        resolver.timeout = self.ctx.config.timeout
                        answers = await resolver.resolve(hostname, qtype)
                        for rdata in answers:
                            ip = rdata.address
                            if ip not in ip_addresses:
                                ip_addresses.append(ip)
                                # PTR lookup
                                ptr = await self._ptr_lookup(ip)
                                if ptr:
                                    ptr_records.append(ptr)
                    except Exception:
                        pass

            if ip_addresses:
                await self.ctx.store.update_host(
                    hostname,
                    ip_addresses=ip_addresses,
                    ptr_records=ptr_records,
                )

    async def _ptr_lookup(self, ip: str) -> Optional[str]:
        if not DNS_AVAILABLE:
            return None
        try:
            rev_name = dns.reversename.from_address(ip)
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 2.0
            answers = await resolver.resolve(rev_name, "PTR")
            return answers[0].to_text().rstrip(".")
        except Exception:
            return None
