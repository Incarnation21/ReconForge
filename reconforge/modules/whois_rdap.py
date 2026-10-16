"""
WHOIS/RDAP Lookup Module.
Queries RDAP (modern REST-based WHOIS replacement) for domain and IP info.
Falls back to traditional WHOIS port 43 socket query.
"""
from __future__ import annotations

import json
import logging
import socket
from typing import Optional

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from reconforge.core.models import WHOISInfo
from reconforge.core.module import BaseModule, ModuleResult, register_module
from reconforge.core.context import ScanContext

logger = logging.getLogger(__name__)

IANA_RDAP_URL = "https://rdap.org"


@register_module
class WHOISRDAPModule(BaseModule):
    NAME = "whois_rdap"
    DESCRIPTION = "RDAP/WHOIS lookup for domain registrar info and IP ASN data"
    REQUIRES: set[str] = set()
    PROVIDES = {"whois_info"}

    async def run(self) -> ModuleResult:
        target = self.ctx.target
        query = target.domain or target.ip or target.raw

        whois_info = await self._rdap_lookup(query)
        if not whois_info:
            whois_info = await self.ctx.run_in_executor(self._whois43_lookup, query)

        if whois_info:
            host = await self.ctx.store.get_or_create_host(query)
            await self.ctx.store.update_host(query, whois_info=whois_info)

        return ModuleResult(
            module_name=self.NAME,
            success=whois_info is not None,
            data={"registrar": whois_info.registrar if whois_info else None},
        )

    async def _rdap_lookup(self, query: str) -> Optional[WHOISInfo]:
        if not AIOHTTP_AVAILABLE:
            return None
        try:
            import ipaddress
            try:
                ipaddress.ip_address(query)
                url = f"{IANA_RDAP_URL}/ip/{query}"
            except ValueError:
                url = f"{IANA_RDAP_URL}/domain/{query}"

            timeout = aiohttp.ClientTimeout(total=15)
            headers = {"Accept": "application/rdap+json", "User-Agent": self.ctx.config.user_agent}
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        return self._parse_rdap(query, data)
        except Exception as e:
            self.logger.debug(f"RDAP lookup failed for {query}: {e}")
        return None

    def _parse_rdap(self, query: str, data: dict) -> WHOISInfo:
        info = WHOISInfo(query=query, raw=data)

        # Entity parsing (registrar, registrant)
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])
            if vcard and len(vcard) > 1:
                for prop in vcard[1]:
                    if prop[0] == "fn":
                        if "registrar" in roles:
                            info.registrar = prop[3]
                        elif "registrant" in roles:
                            info.registrant_org = prop[3]

        # Dates
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action == "registration":
                info.creation_date = date
            elif action == "expiration":
                info.expiration_date = date

        # Nameservers
        for ns in data.get("nameservers", []):
            info.name_servers.append(ns.get("ldhName", "").lower())

        # IP/ASN info
        for link in data.get("links", []):
            pass

        info.asn = str(data.get("aut-num", data.get("autnums", [""])[0] if data.get("autnums") else ""))
        info.country = data.get("country", "")
        info.cidr = data.get("cidr0_cidrs", [""])[0].get("v4prefix", "") if data.get("cidr0_cidrs") else ""

        return info

    def _whois43_lookup(self, query: str) -> Optional[WHOISInfo]:
        """Traditional WHOIS port 43 socket fallback."""
        whois_servers = {
            "default": "whois.iana.org",
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
        }
        try:
            tld = query.split(".")[-1].lower() if "." in query else ""
            server = whois_servers.get(tld, whois_servers["default"])

            with socket.create_connection((server, 43), timeout=10) as sock:
                sock.sendall(f"{query}\r\n".encode())
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

            raw_text = response.decode("utf-8", errors="replace")
            return self._parse_whois43(query, raw_text)
        except Exception as e:
            self.logger.debug(f"WHOIS port 43 failed for {query}: {e}")
        return None

    def _parse_whois43(self, query: str, raw: str) -> WHOISInfo:
        info = WHOISInfo(query=query)
        lines = raw.split("\n")
        for line in lines:
            line = line.strip()
            low = line.lower()
            if low.startswith("registrar:"):
                info.registrar = line.split(":", 1)[1].strip()
            elif low.startswith("creation date:") or low.startswith("created:"):
                info.creation_date = line.split(":", 1)[1].strip()
            elif low.startswith("registry expiry date:") or low.startswith("expir"):
                info.expiration_date = line.split(":", 1)[1].strip()
            elif "name server" in low:
                ns = line.split(":", 1)[1].strip().lower() if ":" in line else ""
                if ns and ns not in info.name_servers:
                    info.name_servers.append(ns)
        return info
