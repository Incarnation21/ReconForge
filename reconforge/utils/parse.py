"""
Parsing utilities for HTML, headers, certificates, and URLs.
"""
from __future__ import annotations

import html
import re
from urllib.parse import urlparse


def extract_html_title(content: str) -> str:
    """Extract and sanitize title from HTML response."""
    match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
    if match:
        title = match.group(1).strip()
        # Decode HTML entities and replace excessive whitespace
        title = html.unescape(title)
        title = re.sub(r"\s+", " ", title)
        return title[:200]
    return ""


def clean_hostname(name: str) -> str:
    """Lowercase and strip trailing dots / wildcards from hostname."""
    name = name.strip().lower()
    if name.startswith("*."):
        name = name[2:]
    return name.rstrip(".")


def parse_target_uri(target: str) -> tuple[str, int | None, str | None]:
    """
    Parse a target string into (host, port, scheme).
    Accepts domains, IPs, URLs, and host:port pairs.
    """
    target = target.strip()
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return (parsed.hostname or "", parsed.port, parsed.scheme)
    
    if ":" in target and not target.startswith("["):
        parts = target.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return (parts[0], int(parts[1]), None)
            
    return (target, None, None)
