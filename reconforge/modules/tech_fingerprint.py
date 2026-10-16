"""
Technology Fingerprinting Module.
Identifies web technologies using multi-vector detection:
  - HTTP headers (Server, X-Powered-By, etc.)
  - Cookie names (PHPSESSID, JSESSIONID, etc.)
  - HTML meta generator tags
  - HTML body regex patterns
  - Favicon MurmurHash3 matching (Shodan-style)
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
from typing import Optional

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import mmh3
    MMH3_AVAILABLE = True
except ImportError:
    MMH3_AVAILABLE = False

from reconforge.core.module import BaseModule, ModuleResult, register_module
from reconforge.core.context import ScanContext

logger = logging.getLogger(__name__)

# Technology signatures: (pattern, field, weight, tech_name)
TECH_SIGNATURES: list[tuple[str, str, int, str]] = [
    # Header-based
    (r"php", "server", 2, "PHP"),
    (r"apache", "server", 3, "Apache"),
    (r"nginx", "server", 3, "Nginx"),
    (r"microsoft-iis", "server", 3, "IIS"),
    (r"cloudflare", "server", 3, "Cloudflare"),
    (r"x-powered-by.*php", "header", 3, "PHP"),
    (r"x-powered-by.*asp", "header", 3, "ASP.NET"),
    (r"x-powered-by.*express", "header", 3, "Node.js/Express"),
    (r"x-aspnet-version", "header", 3, "ASP.NET"),
    (r"x-generator.*wordpress", "header", 3, "WordPress"),
    # Cookie-based
    (r"PHPSESSID", "cookie", 3, "PHP"),
    (r"JSESSIONID", "cookie", 3, "Java/Tomcat"),
    (r"ASP\.NET_SessionId", "cookie", 3, "ASP.NET"),
    (r"laravel_session", "cookie", 3, "Laravel"),
    (r"django", "cookie", 2, "Django"),
    (r"_rails", "cookie", 2, "Ruby on Rails"),
    # HTML body regex
    (r"wp-content|wp-includes|wordpress", "body", 3, "WordPress"),
    (r"Drupal\.settings|drupal\.js", "body", 3, "Drupal"),
    (r"joomla|/components/com_", "body", 3, "Joomla"),
    (r"ng-version|angular\.min\.js", "body", 3, "Angular"),
    (r"react\.development|reactDOM", "body", 2, "React"),
    (r"vue\.min\.js|vue@", "body", 2, "Vue.js"),
    (r"jquery[.-]([\d.]+)\.min\.js", "body", 1, "jQuery"),
    (r"bootstrap\.min\.js|bootstrap\.bundle", "body", 1, "Bootstrap"),
    (r"<meta[^>]+generator[^>]+WordPress", "body", 3, "WordPress"),
    (r"<meta[^>]+generator[^>]+Joomla", "body", 3, "Joomla"),
    (r"<meta[^>]+generator[^>]+Drupal", "body", 3, "Drupal"),
    # Spring Boot Actuator
    (r"/actuator/health|spring\.boot", "body", 3, "Spring Boot"),
    (r"Whitelabel Error Page", "body", 3, "Spring Boot"),
    # Jenkins
    (r"Jenkins", "body", 3, "Jenkins"),
    (r"X-Jenkins", "header", 3, "Jenkins"),
]

# Known favicon hashes (Shodan-style mmh3 hashes)
FAVICON_HASHES: dict[int, str] = {
    -247388890: "Kibana",
    -1641706112: "Jenkins",
    1230051379: "pfSense",
    708578229: "Spring Boot",
    -875985814: "GitLab",
    999357577: "Grafana",
    522371352: "Netdata",
    -1857691851: "Apache Superset",
}


@register_module
class TechFingerprintModule(BaseModule):
    NAME = "tech_fingerprint"
    DESCRIPTION = "Multi-vector technology fingerprinting via headers, cookies, body patterns, and favicon hash"
    REQUIRES = {"http_services"}
    PROVIDES = {"technologies"}

    async def run(self) -> ModuleResult:
        hosts = self.ctx.store.get_all_hosts()
        tech_count = 0
        sem = asyncio.Semaphore(30)

        for hostname in hosts:
            host = self.ctx.store.get_host(hostname)
            if not host or not host.http_services:
                continue

            all_techs: set[str] = set()
            for service in host.http_services:
                if service.status_code <= 0:
                    continue
                techs = await self._fingerprint_service(service, sem)
                all_techs.update(techs)
                service.technologies = list(techs)

            if all_techs:
                tech_count += len(all_techs)
                await self.ctx.store.update_host(hostname, technologies=list(all_techs))

        return ModuleResult(
            module_name=self.NAME,
            success=True,
            data={"unique_technologies": tech_count},
        )

    async def _fingerprint_service(self, service, sem: asyncio.Semaphore) -> set[str]:
        detected: dict[str, int] = {}  # tech -> weight

        headers_str = " ".join(f"{k}:{v}" for k, v in service.headers.items()).lower()
        server_str = service.server.lower()
        cookies_str = " ".join(service.headers.get("Set-Cookie", "").split(";[,]"))

        # Fetch body content if not already available
        body_str = ""
        if AIOHTTP_AVAILABLE and service.url:
            async with sem:
                body_str = await self._fetch_body(service.url)

        for pattern, field, weight, tech in TECH_SIGNATURES:
            target_str = {
                "server": server_str,
                "header": headers_str,
                "cookie": cookies_str,
                "body": body_str,
            }.get(field, "")

            if re.search(pattern, target_str, re.IGNORECASE):
                detected[tech] = detected.get(tech, 0) + weight

        # Favicon hash
        if AIOHTTP_AVAILABLE:
            favicon_tech = await self._check_favicon(service.url, sem)
            if favicon_tech:
                detected[favicon_tech] = detected.get(favicon_tech, 0) + 5

        # Return techs that meet detection threshold
        return {tech for tech, weight in detected.items() if weight >= 2}

    async def _fetch_body(self, url: str) -> str:
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    content = await resp.read()
                    return content.decode("utf-8", errors="replace")[:50000]
        except Exception:
            return ""

    async def _check_favicon(self, base_url: str, sem: asyncio.Semaphore) -> Optional[str]:
        if not MMH3_AVAILABLE:
            return None
        try:
            favicon_url = base_url.rstrip("/") + "/favicon.ico"
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(favicon_url, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.read()
                        favicon_b64 = base64.encodebytes(content)
                        favicon_hash = mmh3.hash(favicon_b64)
                        return FAVICON_HASHES.get(favicon_hash)
        except Exception:
            pass
        return None
