"""
Scope enforcement and target normalization.
All targets are validated against allowed scope before scanning begins.
Private/reserved IP ranges are protected by default.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
from typing import Optional
from urllib.parse import urlparse

from .models import Target, TargetType

logger = logging.getLogger(__name__)

# RFC 1918 and reserved ranges protected by default
PROTECTED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("224.0.0.0/4"),
]

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class ScopeViolationError(Exception):
    """Raised when a target falls outside the defined scope."""
    pass


class ScopeValidator:
    """Validates and enforces scan scope boundaries."""

    def __init__(
        self,
        allowed_domains: Optional[list[str]] = None,
        allowed_cidrs: Optional[list[str]] = None,
        scope_file: Optional[str] = None,
        allow_private: bool = False,
    ):
        self.allowed_domains: list[str] = allowed_domains or []
        self.allowed_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.allow_private = allow_private

        if allowed_cidrs:
            for cidr in allowed_cidrs:
                try:
                    self.allowed_cidrs.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    logger.warning(f"Invalid CIDR in scope: {cidr}")

        if scope_file:
            self._load_scope_file(scope_file)

    def _load_scope_file(self, path: str) -> None:
        """Load scope from a newline-delimited file."""
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        self.allowed_cidrs.append(net)
                    except ValueError:
                        # Treat as domain
                        self.allowed_domains.append(line)
        except FileNotFoundError:
            logger.error(f"Scope file not found: {path}")

    def is_ip_protected(self, ip_str: str) -> bool:
        """Check if IP falls in a protected/private range."""
        if self.allow_private:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in PROTECTED_RANGES)
        except ValueError:
            return False

    def is_in_scope(self, value: str) -> bool:
        """Check if a domain or IP is within defined scope."""
        # If no scope defined, allow all (but still block private)
        if not self.allowed_domains and not self.allowed_cidrs:
            return True

        # Check IP/CIDR scope
        try:
            addr = ipaddress.ip_address(value)
            return any(addr in net for net in self.allowed_cidrs)
        except ValueError:
            pass

        # Check domain scope
        value_lower = value.lower()
        for domain in self.allowed_domains:
            domain_lower = domain.lower()
            if value_lower == domain_lower or value_lower.endswith("." + domain_lower):
                return True

        return False

    def validate(self, value: str) -> None:
        """Raise ScopeViolationError if value is out of scope."""
        try:
            addr = ipaddress.ip_address(value)
            if not self.allow_private and any(addr in net for net in PROTECTED_RANGES):
                raise ScopeViolationError(
                    f"Target {value} is a private/reserved IP address. "
                    "Use --allow-private to override (only on networks you own)."
                )
        except ValueError:
            pass  # Not an IP, continue to domain check

        if not self.is_in_scope(value):
            raise ScopeViolationError(
                f"Target {value} is outside defined scan scope."
            )


def normalize_target(raw: str) -> Target:
    """Parse and normalize a raw target string into a Target object."""
    raw = raw.strip()

    # URL detection
    if raw.startswith(("http://", "https://", "ftp://")):
        parsed = urlparse(raw)
        hostname = parsed.hostname or ""
        port = parsed.port
        scheme = parsed.scheme
        try:
            ipaddress.ip_address(hostname)
            return Target(
                raw=raw,
                type=TargetType.URL,
                ip=hostname,
                url=raw,
                port=port,
                scheme=scheme,
            )
        except ValueError:
            return Target(
                raw=raw,
                type=TargetType.URL,
                domain=hostname,
                url=raw,
                port=port,
                scheme=scheme,
            )

    # CIDR detection
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return Target(
                raw=raw,
                type=TargetType.CIDR,
                cidr=net,
            )
        except ValueError:
            pass

    # IP detection
    try:
        addr = ipaddress.ip_address(raw)
        return Target(
            raw=raw,
            type=TargetType.IP,
            ip=str(addr),
        )
    except ValueError:
        pass

    # IP:Port detection
    if ":" in raw and not raw.startswith("["):
        parts = raw.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            try:
                addr = ipaddress.ip_address(parts[0])
                return Target(
                    raw=raw,
                    type=TargetType.IP,
                    ip=str(addr),
                    port=int(parts[1]),
                )
            except ValueError:
                pass

    # Domain
    if DOMAIN_PATTERN.match(raw):
        return Target(
            raw=raw,
            type=TargetType.DOMAIN,
            domain=raw.lower(),
        )

    # Last resort: try resolving it
    logger.warning(f"Could not classify target '{raw}', treating as domain")
    return Target(
        raw=raw,
        type=TargetType.DOMAIN,
        domain=raw.lower(),
    )
