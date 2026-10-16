"""
Subdomain Enumeration Module.
Combines passive Certificate Transparency (crt.sh) with active wordlist brute-forcing.
Includes wildcard DNS baseline detection to eliminate false positives.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import string
from typing import Optional

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import dns.asyncresolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from reconforge.core.models import Finding, Severity
from reconforge.core.module import BaseModule, ModuleResult, register_module
from reconforge.core.context import ScanContext

logger = logging.getLogger(__name__)

DEFAULT_WORDLIST_PATHS = [
    os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", "subdomains.txt"),
    "/usr/share/wordlists/subdomains.txt",
]


@register_module
class SubdomainModule(BaseModule):
    NAME = "subdomain"
    DESCRIPTION = "Passive CT log + active wordlist subdomain enumeration with wildcard suppression"
    REQUIRES: set[str] = set()
    PROVIDES = {"subdomains"}

    def __init__(self, ctx: ScanContext):
        super().__init__(ctx)
        self.domain: Optional[str] = None
        self.wildcard_ips: set[str] = set()

    async def run(self) -> ModuleResult:
        target = self.ctx.target
        if not target.domain:
            return ModuleResult(module_name=self.NAME, success=False, errors=["No domain target"])

        self.domain = target.domain
        discovered: dict[str, str] = {}  # hostname -> source

        # Step 1: Detect wildcard DNS
        await self._detect_wildcard()

        # Step 2: Passive - Certificate Transparency
        ct_subs = await self._fetch_crtsh()
        for sub in ct_subs:
            discovered[sub] = "crtsh"
        self.logger.info(f"crt.sh: found {len(ct_subs)} subdomains")

        # Step 3: Active - wordlist brute force
        brute_subs = await self._brute_force()
        for sub in brute_subs:
            if sub not in discovered:
                discovered[sub] = "brute"
        self.logger.info(f"Brute force: found {len(brute_subs)} additional subdomains")

        # Create host records for all discovered subdomains
        for hostname, source in discovered.items():
            await self.ctx.store.get_or_create_host(hostname)
            await self.ctx.store.update_host(hostname, subdomain_source=source)

        self.ctx.set("subdomains", list(discovered.keys()))
        return ModuleResult(
            module_name=self.NAME,
            success=True,
            data={"total": len(discovered), "from_crtsh": len(ct_subs), "from_brute": len(brute_subs)},
        )

    async def _detect_wildcard(self) -> None:
        """Resolve 3 random subdomains to detect wildcard DNS responses."""
        if not DNS_AVAILABLE:
            return
        for _ in range(3):
            rand_sub = f"{''.join(random.choices(string.ascii_lowercase, k=16))}.{self.domain}"
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = 3.0
                answers = await resolver.resolve(rand_sub, "A")
                for rdata in answers:
                    self.wildcard_ips.add(rdata.address)
            except Exception:
                pass
        if self.wildcard_ips:
            self.logger.warning(f"Wildcard DNS detected for {self.domain}: {self.wildcard_ips}")

    async def _fetch_crtsh(self) -> list[str]:
        """Fetch subdomains from crt.sh Certificate Transparency logs."""
        if not AIOHTTP_AVAILABLE:
            return []
        subdomains = set()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            timeout = aiohttp.ClientTimeout(total=20)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lower().lstrip("*.").strip()
                                if sub and sub.endswith(self.domain) and sub != self.domain:
                                    subdomains.add(sub)
        except Exception as e:
            self.logger.debug(f"crt.sh failed: {e}")
        return list(subdomains)

    async def _brute_force(self) -> list[str]:
        """Actively resolve wordlist subdomains."""
        if not DNS_AVAILABLE:
            return []
        wordlist = self._load_wordlist()
        if not wordlist:
            return []

        found = []
        sem = asyncio.Semaphore(100)

        async def resolve_one(word: str) -> Optional[str]:
            subdomain = f"{word}.{self.domain}"
            async with sem:
                try:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.timeout = 2.0
                    answers = await resolver.resolve(subdomain, "A")
                    resolved_ips = {rdata.address for rdata in answers}
                    # Suppress wildcard matches
                    if self.wildcard_ips and resolved_ips.issubset(self.wildcard_ips):
                        return None
                    return subdomain
                except Exception:
                    return None

        tasks = [resolve_one(w) for w in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, str):
                found.append(r)
        return found

    def _load_wordlist(self) -> list[str]:
        """Load subdomain wordlist from configured or default paths."""
        paths = []
        if self.ctx.config.wordlist:
            paths.append(self.ctx.config.wordlist)
        paths.extend(DEFAULT_WORDLIST_PATHS)

        for path in paths:
            path = os.path.abspath(path)
            if os.path.exists(path):
                with open(path, "r", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                self.logger.info(f"Loaded {len(words)} words from {path}")
                return words

        # Fallback: built-in minimal wordlist
        self.logger.warning("No wordlist found, using built-in minimal list")
        return [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "blog",
            "shop", "portal", "app", "vpn", "remote", "secure", "webmail", "cdn",
            "static", "assets", "media", "files", "docs", "support", "help",
            "m", "mobile", "beta", "demo", "dashboard", "login", "auth", "sso",
            "ns1", "ns2", "mx", "smtp", "imap", "pop", "autodiscover", "owa",
            "git", "gitlab", "jira", "jenkins", "ci", "cd", "docker", "k8s",
            "kubernetes", "grafana", "kibana", "elastic", "redis", "mongo",
            "db", "database", "mysql", "postgres", "backup", "internal",
        ]
