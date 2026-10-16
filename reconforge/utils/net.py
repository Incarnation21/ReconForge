"""
Network utility functions for ReconForge.
Handles IP parsing, CIDR expansion, hostname resolution, and socket helpers.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Iterator


def is_ip(address: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_private_ip(address: str) -> bool:
    """Check if IP address is in a private/reserved/loopback range."""
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def expand_cidr(cidr_str: str, max_hosts: int = 256) -> list[str]:
    """
    Expand a CIDR notation into a list of host IPs.
    Caps expansion at max_hosts to avoid accidental resource exhaustion.
    """
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        hosts = []
        for i, ip in enumerate(network.hosts()):
            if i >= max_hosts:
                break
            hosts.append(str(ip))
        return hosts
    except ValueError:
        return []


def format_endpoint(host: str, port: int, scheme: str = "http") -> str:
    """Format an endpoint URL with host and port."""
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"
