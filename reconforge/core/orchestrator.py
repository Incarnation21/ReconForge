"""
DAG-based module orchestrator for ReconForge.
Modules are organized into stages based on their REQUIRES/PROVIDES dependencies.
Intra-stage modules run concurrently; stages run sequentially.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import time
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

from .context import ScanContext, ScanConfig
from .models import ScanResult, Target
from .module import BaseModule, ModuleResult, get_registry
from .scope import ScopeViolationError

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Ordered stages: each list contains module names that can run concurrently.
# A module in stage N can use data produced by modules in stages 0..N-1.
DEFAULT_PIPELINE: list[list[str]] = [
    ["dns_enum"],
    ["subdomain", "whois_rdap"],
    ["ip_resolve"],
    ["portscan"],
    ["http_probe"],
    ["tech_fingerprint", "dir_enum", "tls_inspect"],
]


class Orchestrator:
    """Manages module execution across pipeline stages."""

    def __init__(self, ctx: ScanContext, pipeline: Optional[list[list[str]]] = None):
        self.ctx = ctx
        self.pipeline = pipeline or DEFAULT_PIPELINE
        self._modules: dict[str, BaseModule] = {}
        self._shutdown = False
        self._start_time: float = 0.0

        # Import all modules to trigger registration
        self._import_modules()

        # Build active module map from registry + config
        registry = get_registry()
        cfg = ctx.config
        for name, cls in registry.items():
            if cfg.modules and name not in cfg.modules:
                continue
            if name in cfg.skip_modules:
                continue
            if not cls.ENABLED_BY_DEFAULT and name not in cfg.modules:
                continue
            self._modules[name] = cls(ctx)

    def _import_modules(self) -> None:
        """Import module implementations to trigger @register_module decorators."""
        from reconforge.modules import (
            dns_enum,
            subdomain,
            ip_resolve,
            portscan,
            http_probe,
            tech_fingerprint,
            dir_enum,
            tls_inspect,
            whois_rdap,
        )

    def _setup_signal_handlers(self) -> None:
        """Install SIGINT/SIGTERM handlers for graceful shutdown."""
        try:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, self._request_shutdown)
        except (NotImplementedError, RuntimeError):
            # Windows doesn't support add_signal_handler for SIGTERM
            signal.signal(signal.SIGINT, lambda s, f: self._request_shutdown())

    def _request_shutdown(self) -> None:
        logger.warning("Shutdown requested. Completing current stage and saving partial results...")
        self._shutdown = True

    async def run(self) -> ScanResult:
        """Execute the full scan pipeline."""
        self._setup_signal_handlers()
        self._start_time = time.monotonic()
        result = self.ctx.store.result

        logger.info(f"Starting ReconForge scan against: {self.ctx.target.raw}")
        logger.info(f"Active modules: {list(self._modules.keys())}")

        for stage_idx, stage_modules in enumerate(self.pipeline):
            if self._shutdown:
                logger.warning("Stopping pipeline due to shutdown request")
                break

            active = [m for m in stage_modules if m in self._modules]
            if not active:
                logger.debug(f"Stage {stage_idx}: no active modules, skipping")
                continue

            logger.info(f"Stage {stage_idx + 1}/{len(self.pipeline)}: running [{', '.join(active)}]")
            tasks = [
                asyncio.create_task(
                    self._modules[name].safe_run(),
                    name=f"module-{name}",
                )
                for name in active
            ]
            results: list[ModuleResult] = await asyncio.gather(*tasks, return_exceptions=True)

            for i, res in enumerate(results):
                mod_name = active[i]
                if isinstance(res, Exception):
                    logger.error(f"Module {mod_name} raised unhandled exception: {res}")
                elif isinstance(res, ModuleResult):
                    if not res.success:
                        logger.warning(f"Module {mod_name} reported failures: {res.errors}")
                    else:
                        logger.info(f"Module {mod_name} completed successfully")

            # TLS SAN feedback loop: re-run ip_resolve+portscan for new subdomains
            if stage_idx == len(self.pipeline) - 1:
                await self._san_feedback_loop()

        elapsed = time.monotonic() - self._start_time
        result.end_time = datetime.now(timezone.utc)
        logger.info(f"Scan complete in {elapsed:.1f}s. Found {len(result.findings)} findings across {len(result.hosts)} hosts.")

        self.ctx.shutdown()
        return result

    async def _san_feedback_loop(self) -> None:
        """Feed SAN hostnames from TLS certs back into ip_resolve and portscan."""
        if self.ctx.config.resolve_depth < 1:
            return

        san_hosts = set()
        for host in self.ctx.store.result.hosts.values():
            if host.tls_info:
                for san in host.tls_info.san:
                    san = san.strip().lower()
                    if san.startswith("*"):
                        continue  # skip wildcards
                    if san not in self.ctx.store.result.hosts:
                        if self.ctx.scope.is_in_scope(san):
                            san_hosts.add(san)

        if not san_hosts:
            return

        logger.info(f"SAN feedback loop: discovered {len(san_hosts)} new hostnames from TLS certificates")

        # Create stub host records for new SAN hosts
        for hostname in san_hosts:
            await self.ctx.store.get_or_create_host(hostname)

        # Re-run ip_resolve and portscan for new hosts
        for mod_name in ["ip_resolve", "portscan"]:
            if mod_name in self._modules:
                logger.info(f"SAN feedback: running {mod_name} for new hosts")
                await self._modules[mod_name].safe_run()
