"""
HTTP Probe Module.
Probes web services on discovered open ports, follows redirects,
checks security headers, and extracts page metadata.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from reconforge.core.models import Finding, HTTPInfo, Severity
from reconforge.core.module import BaseModule, ModuleResult, register_module
from reconforge.core.context import ScanContext

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS Missing", Severity.MEDIUM, "Missing Strict-Transport-Security header."),
    "content-security-policy": ("CSP Missing", Severity.MEDIUM, "Missing Content-Security-Policy header."),
    "x-frame-options": ("Clickjacking Protection Missing", Severity.MEDIUM, "Missing X-Frame-Options header allows clickjacking."),
    "x-content-type-options": ("MIME Sniffing Protection Missing", Severity.LOW, "Missing X-Content-Type-Options: nosniff"),
    "x-xss-protection": ("XSS Protection Header Missing", Severity.LOW, "Missing X-XSS-Protection header."),
    "referrer-policy": ("Referrer Policy Missing", Severity.LOW, "Missing Referrer-Policy header."),
    "permissions-policy": ("Permissions Policy Missing", Severity.INFO, "Missing Permissions-Policy header."),
}

WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 8008, 8009, 8081, 8082, 8083, 8084, 8085, 8090, 5000, 3000, 4000, 9000]


@register_module
class HTTPProbeModule(BaseModule):
    NAME = "http_probe"
    DESCRIPTION = "HTTP/HTTPS probing, redirect following, security header audit"
    REQUIRES = {"open_ports"}
    PROVIDES = {"http_services", "web_urls"}

    async def run(self) -> ModuleResult:
        if not AIOHTTP_AVAILABLE:
            return ModuleResult(module_name=self.NAME, success=False, errors=["aiohttp not installed"])

        hosts = self.ctx.store.get_all_hosts()
        total_services = 0
        web_urls = []
        sem = asyncio.Semaphore(50)

        for hostname in hosts:
            host = self.ctx.store.get_host(hostname)
            if not host:
                continue

            # Determine which URLs to probe
            urls_to_probe = set()
            for port_info in host.open_ports:
                if port_info.port in WEB_PORTS or port_info.service in ("http", "https", "http-alt", "https-alt"):
                    scheme = "https" if port_info.port in (443, 8443) else "http"
                    url = f"{scheme}://{hostname}:{port_info.port}"
                    urls_to_probe.add(url)

            # Always probe 80/443 if nothing found
            if not urls_to_probe:
                urls_to_probe = {f"http://{hostname}", f"https://{hostname}"}

            tasks = [self._probe_url(url, hostname, sem) for url in urls_to_probe]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            http_services = [r for r in results if isinstance(r, HTTPInfo) and r.status_code > 0]
            if http_services:
                total_services += len(http_services)
                web_urls.extend([s.url for s in http_services])
                await self.ctx.store.update_host(hostname, http_services=http_services)
                await self._check_security_headers(hostname, http_services)

        self.ctx.set("web_urls", web_urls)
        return ModuleResult(
            module_name=self.NAME,
            success=True,
            data={"total_web_services": total_services},
        )

    async def _probe_url(self, url: str, hostname: str, sem: asyncio.Semaphore) -> Optional[HTTPInfo]:
        async with sem:
            try:
                timeout = aiohttp.ClientTimeout(total=self.ctx.config.timeout * 2, connect=self.ctx.config.timeout)
                connector = aiohttp.TCPConnector(ssl=False, limit=50)
                headers = {"User-Agent": self.ctx.config.user_agent}

                redirect_chain = []

                async with aiohttp.ClientSession(
                    timeout=timeout,
                    connector=connector,
                    headers=headers,
                ) as session:
                    async with session.get(
                        url,
                        allow_redirects=True,
                        max_redirects=self.ctx.config.max_redirects,
                        ssl=False,
                    ) as resp:
                        content = await resp.read()
                        final_url = str(resp.url)

                        # Collect redirect chain
                        for hist in resp.history:
                            redirect_chain.append(str(hist.url))
                        if final_url != url:
                            redirect_chain.append(final_url)

                        # Parse title
                        text = content.decode("utf-8", errors="replace")
                        title = self._extract_title(text)

                        headers_dict = dict(resp.headers)
                        server = headers_dict.get("Server", headers_dict.get("server", ""))

                        return HTTPInfo(
                            url=final_url,
                            status_code=resp.status,
                            title=title,
                            server=server,
                            content_type=headers_dict.get("Content-Type", ""),
                            content_length=len(content),
                            redirect_chain=redirect_chain,
                            headers=headers_dict,
                            security_headers=self._audit_security_headers(headers_dict),
                        )
            except Exception as e:
                logger.debug(f"HTTP probe failed for {url}: {e}")
                return HTTPInfo(url=url, status_code=0)

    def _extract_title(self, html: str) -> str:
        m = re.search(r"<title[^>]*>([^<]{1,200})</title>", html, re.IGNORECASE)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()
        return ""

    def _audit_security_headers(self, headers: dict) -> dict:
        lower_headers = {k.lower(): v for k, v in headers.items()}
        audit = {}
        for header_name, (_, _, _) in SECURITY_HEADERS.items():
            present = header_name in lower_headers
            audit[header_name] = {
                "present": present,
                "value": lower_headers.get(header_name, ""),
            }
        return audit

    async def _check_security_headers(self, hostname: str, services: list[HTTPInfo]) -> None:
        for service in services:
            if service.status_code <= 0:
                continue
            for header_name, (title, severity, desc) in SECURITY_HEADERS.items():
                audit = service.security_headers.get(header_name, {})
                if not audit.get("present"):
                    await self.ctx.store.add_finding(Finding(
                        id=self._make_finding_id(f"{hostname}-{header_name}"),
                        title=title,
                        severity=severity,
                        description=f"{desc} URL: {service.url}",
                        target=hostname,
                        module=self.NAME,
                        recommendation=f"Add the '{header_name}' HTTP response header.",
                        cwe="CWE-693",
                    ))

            # Check for server version disclosure
            if service.server and any(c.isdigit() for c in service.server):
                await self.ctx.store.add_finding(Finding(
                    id=self._make_finding_id(f"{hostname}-server-disclosure"),
                    title="Server Version Disclosure",
                    severity=Severity.LOW,
                    description=f"Server header reveals version: '{service.server}'",
                    target=hostname,
                    module=self.NAME,
                    evidence=f"Server: {service.server}",
                    recommendation="Configure your web server to omit or genericize the Server header.",
                    cwe="CWE-200",
                ))
