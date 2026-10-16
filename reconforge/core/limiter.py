"""
Token-bucket rate limiter with async semaphore integration.
Provides two-tier concurrency control:
  1. Global token-bucket rate limit (requests/second)
  2. Per-module concurrency semaphores
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class TokenBucket:
    """Thread/async-safe token bucket for rate limiting."""
    rate: float  # tokens per second
    capacity: float  # max burst
    _tokens: float = 0.0
    _last_refill: float = 0.0
    _lock: Optional[asyncio.Lock] = None

    def __post_init__(self):
        self._tokens = self.capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        """Wait until `tokens` tokens are available, then consume them."""
        assert self._lock is not None
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(
                    self.capacity,
                    self._tokens + elapsed * self.rate
                )
                self._last_refill = now

                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return

            # Not enough tokens, wait a bit and retry
            wait_time = (tokens - self._tokens) / self.rate
            await asyncio.sleep(max(0.001, wait_time))


class RateLimiter:
    """
    Two-tier rate limiter for ReconForge.
    Combines a global token-bucket with per-module semaphores.
    """

    # Default per-module concurrency caps
    MODULE_CONCURRENCY = {
        "portscan": 500,
        "http_probe": 50,
        "dns_enum": 100,
        "subdomain": 100,
        "dir_enum": 30,
        "tls_inspect": 30,
        "tech_fingerprint": 50,
        "whois_rdap": 10,
        "ip_resolve": 100,
        "default": 50,
    }

    def __init__(self, global_rate: float = 100.0, global_concurrency: int = 200):
        self.bucket = TokenBucket(rate=global_rate, capacity=min(global_rate * 2, 500))
        self.global_sem = asyncio.Semaphore(global_concurrency)
        self._module_sems: dict[str, asyncio.Semaphore] = {}

    def get_module_sem(self, module_name: str) -> asyncio.Semaphore:
        """Get or create a per-module semaphore."""
        if module_name not in self._module_sems:
            cap = self.MODULE_CONCURRENCY.get(module_name, self.MODULE_CONCURRENCY["default"])
            self._module_sems[module_name] = asyncio.Semaphore(cap)
        return self._module_sems[module_name]

    async def acquire(self, module_name: str = "default", tokens: float = 1.0) -> None:
        """Acquire global + module semaphore + token bucket."""
        await self.bucket.acquire(tokens)
        await self.global_sem.acquire()
        await self.get_module_sem(module_name).acquire()

    def release(self, module_name: str = "default") -> None:
        """Release global + module semaphores."""
        self.get_module_sem(module_name).release()
        self.global_sem.release()


class RateLimitContext:
    """Async context manager for rate-limited operations."""

    def __init__(self, limiter: RateLimiter, module_name: str = "default"):
        self.limiter = limiter
        self.module_name = module_name

    async def __aenter__(self):
        await self.limiter.acquire(self.module_name)
        return self

    async def __aexit__(self, *args):
        self.limiter.release(self.module_name)
