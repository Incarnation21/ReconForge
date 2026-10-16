"""
Directory/Path Enumeration Module.
Uses a 3-request baseline calibration to detect soft-404 responses
before brute-forcing paths. Flags sensitive file patterns.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from typing import Optional

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from reconforge.core.models import Finding, Severity
from reconforge.core.module import BaseModule, ModuleResult, register_module
from reconforge.core.context import ScanContext

logger = logging.getLogger(__name__)

SENSITIVE_PATHS = {
    "/.git/HEAD": (Severity.CRITICAL, "Git Repository Exposed", "Source code and credentials may be exposed via .git directory."),
    "/.env": (Severity.CRITICAL, "Environment File Exposed", ".env file may contain database credentials and API keys."),
    "/.git/config": (Severity.CRITICAL, "Git Config Exposed", "Git configuration file exposed."),
    "/wp-config.php.bak": (Severity.HIGH, "WordPress Config Backup Exposed", "WordPress configuration backup may contain DB credentials."),
    "/config.php.bak": (Severity.HIGH, "Config Backup File Exposed", "PHP configuration backup exposed."),
    "/backup.sql": (Severity.HIGH, "SQL Backup Exposed", "Database backup file publicly accessible."),
    "/backup.zip": (Severity.HIGH, "Backup Archive Exposed", "Backup archive publicly accessible."),
    "/phpinfo.php": (Severity.MEDIUM, "PHPInfo Page Exposed", "PHP configuration details publicly accessible."),
    "/server-status": (Severity.MEDIUM, "Apache Server Status Exposed", "Apache mod_status exposes server internals."),
    "/actuator": (Severity.HIGH, "Spring Boot Actuator Exposed", "Spring Boot actuator endpoints may expose sensitive data."),
    "/actuator/env": (Severity.CRITICAL, "Spring Boot Actuator /env Exposed", "Environment variables including secrets exposed."),
    "/api/swagger": (Severity.INFO, "Swagger API Docs Found", "API documentation may expose endpoint details."),
    "/swagger-ui.html": (Severity.INFO, "Swagger UI Found", "Swagger interface exposed."),
    "/robots.txt": (Severity.INFO, "Robots.txt Found", "robots.txt may reveal hidden paths."),
    "/sitemap.xml": (Severity.INFO, "Sitemap Found", "sitemap.xml reveals site structure."),
    "/.well-known/security.txt": (Severity.INFO, "Security.txt Found", "Security disclosure policy found."),
}

DEFAULT_DIR_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "panel", "cp", "cpanel",
    "wp-admin", "wp-login.php", "wp-config.php", "xmlrpc.php",
    "api", "api/v1", "api/v2", "api/v3", "rest", "graphql",
    "upload", "uploads", "files", "static", "assets", "media", "images",
    "backup", "backups", "old", "archive", "tmp", "temp",
    "config", "conf", "configuration", "settings",
    "install", "setup", "installer",
    "phpmyadmin", "pma", "mysql", "db", "database",
    "console", "manager", "management",
    "test", "testing", "debug", "dev", "development",
    "log", "logs", "error", "errors",
    "shell", "cmd", "exec",
    "user", "users", "account", "accounts", "profile",
    "checkout", "cart", "order", "payment",
    "search", "index.php", "default.php",
]


@register_module
class DirEnumModule(BaseModule):
    NAME = "dir_enum"
    DESCRIPTION = "Directory brute-forcing with soft-404 calibration and sensitive path detection"
    REQUIRES = {"http_services"}
    PROVIDES = {"directories"}

    async def run(self) -> ModuleResult:
        if not AIOHTTP_AVAILABLE:
            return ModuleResult(module_name=self.NAME, success=False, errors=["aiohttp not installed"])

        hosts = self.ctx.store.get_all_hosts()
        total_found = 0
        sem = asyncio.Semaphore(30)

        for hostname in hosts:
            host = self.ctx.store.get_host(hostname)
            if not host or not host.http_services:
                continue

            for service in host.http_services:
                if service.status_code <= 0:
                    continue
                base_url = service.url.rstrip("/")

                # First: check sensitive paths
                sensitive = await self._check_sensitive_paths(base_url, hostname, sem)

                # Then: brute-force general dirs
                wordlist = self._load_wordlist()
                soft404_signatures = await self._calibrate_soft404(base_url, sem)
                general_dirs = await self._brute_dirs(base_url, wordlist, soft404_signatures, sem)

                all_dirs = sensitive + general_dirs
                total_found += len(all_dirs)

                if all_dirs:
                    await self.ctx.store.update_host(hostname, directories=all_dirs)

        return ModuleResult(
            module_name=self.NAME,
            success=True,
            data={"total_paths_found": total_found},
        )

    async def _calibrate_soft404(self, base_url: str, sem: asyncio.Semaphore) -> set[str]:
        """Send 3 requests to random paths to establish a 404 baseline."""
        import uuid
        soft404_bodies: set[str] = set()
        for _ in range(3):
            path = f"/{uuid.uuid4().hex}"
            body = await self._get_body_hash(base_url + path, sem)
            if body:
                soft404_bodies.add(body)
        return soft404_bodies

    async def _get_body_hash(self, url: str, sem: asyncio.Semaphore) -> Optional[str]:
        async with sem:
            try:
                timeout = aiohttp.ClientTimeout(total=self.ctx.config.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, ssl=False, allow_redirects=False) as resp:
                        body = await resp.read()
                        if resp.status in (404, 410):
                            return hashlib.md5(body[:512]).hexdigest()
            except Exception:
                pass
        return None

    async def _check_sensitive_paths(self, base_url: str, hostname: str, sem: asyncio.Semaphore) -> list[dict]:
        found = []
        tasks = [self._probe_path(base_url, path, sem) for path in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for path, result in zip(SENSITIVE_PATHS.keys(), results):
            if isinstance(result, dict) and result.get("status") in (200, 301, 302, 403):
                severity, title, desc = SENSITIVE_PATHS[path]
                found.append(result)
                await self.ctx.store.add_finding(Finding(
                    id=self._make_finding_id(f"{hostname}-{path.replace('/', '-')}"),
                    title=title,
                    severity=severity,
                    description=f"{desc} Found at: {base_url}{path}",
                    target=hostname,
                    module=self.NAME,
                    evidence=f"HTTP {result.get('status')} at {base_url}{path}",
                    recommendation="Restrict access to sensitive files and directories using web server configuration.",
                    cwe="CWE-538",
                ))
        return found

    async def _brute_dirs(self, base_url: str, wordlist: list[str], soft404: set[str], sem: asyncio.Semaphore) -> list[dict]:
        found = []
        tasks = [self._probe_path(base_url, f"/{word}", sem) for word in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict):
                status = result.get("status", 0)
                if status in (200, 301, 302, 403):
                    body_hash = result.get("body_hash", "")
                    if body_hash not in soft404:
                        found.append(result)
        return found

    async def _probe_path(self, base_url: str, path: str, sem: asyncio.Semaphore) -> dict:
        async with sem:
            try:
                url = base_url + path
                timeout = aiohttp.ClientTimeout(total=self.ctx.config.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, ssl=False, allow_redirects=False) as resp:
                        body = await resp.read()
                        return {
                            "path": path,
                            "url": url,
                            "status": resp.status,
                            "content_length": len(body),
                            "body_hash": hashlib.md5(body[:512]).hexdigest(),
                        }
            except Exception:
                return {"path": path, "url": base_url + path, "status": 0}

    def _load_wordlist(self) -> list[str]:
        if self.ctx.config.dir_wordlist and os.path.exists(self.ctx.config.dir_wordlist):
            with open(self.ctx.config.dir_wordlist, "r", errors="ignore") as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return DEFAULT_DIR_WORDLIST
