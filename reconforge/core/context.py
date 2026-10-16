"""
Scan context - the shared state object passed to all modules.
Contains configuration, the result store, rate limiter, and executor.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from dataclasses import dataclass, field
from typing import Optional

from .limiter import RateLimiter
from .models import ScanResult, Target
from .scope import ScopeValidator
from .store import ResultStore

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """All user-facing configuration options for a scan."""
    # Authorization
    authorized: bool = False

    # Target scope
    scope_file: Optional[str] = None
    allowed_domains: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    allow_private: bool = False

    # Module selection
    modules: list[str] = field(default_factory=list)  # empty = all enabled
    skip_modules: list[str] = field(default_factory=list)

    # Network settings
    rate: float = 100.0          # global requests/sec
    concurrency: int = 200       # global async concurrency
    timeout: float = 5.0         # per-connection timeout (seconds)
    retries: int = 2             # retry attempts
    user_agent: str = "Mozilla/5.0 (compatible; ReconForge/1.0; +https://github.com/reconforge)"

    # Port scan settings
    ports: str = "top1000"       # 'top100', 'top1000', 'all', or comma list
    use_nmap: bool = False        # use nmap as secondary engine

    # HTTP settings
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = False      # for recon, skip TLS verification to see misconfigured certs

    # Subdomain / dir enum
    wordlist: Optional[str] = None
    dir_wordlist: Optional[str] = None
    resolve_depth: int = 1        # SAN feedback loop iterations

    # Output
    output_dir: str = "."
    output_format: list[str] = field(default_factory=lambda: ["json", "html"])
    verbose: bool = False
    no_color: bool = False


class ScanContext:
    """Shared context object provided to all scan modules."""

    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        scan_result: ScanResult,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self.target = target
        self.config = config
        self.store = ResultStore(scan_result)
        self.limiter = RateLimiter(
            global_rate=config.rate,
            global_concurrency=config.concurrency,
        )
        self.scope = ScopeValidator(
            allowed_domains=config.allowed_domains,
            allowed_cidrs=config.allowed_cidrs,
            scope_file=config.scope_file,
            allow_private=config.allow_private,
        )
        # Thread pool for blocking I/O
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(32, (config.concurrency // 10) + 4),
            thread_name_prefix="reconforge-worker",
        )
        self._loop = loop or asyncio.get_event_loop()

        # Shared data passed between module stages
        self._shared: dict = {}

    def set(self, key: str, value) -> None:
        """Store a value in shared context data."""
        self._shared[key] = value

    def get(self, key: str, default=None):
        """Retrieve a value from shared context data."""
        return self._shared.get(key, default)

    def has(self, key: str) -> bool:
        """Check if a key exists in shared context data."""
        return key in self._shared

    async def run_in_executor(self, fn, *args):
        """Run a blocking function in the thread pool."""
        return await self._loop.run_in_executor(self.executor, fn, *args)

    def shutdown(self):
        """Clean up thread pool executor."""
        self.executor.shutdown(wait=False)
