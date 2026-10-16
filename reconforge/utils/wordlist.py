"""
Wordlist loading and stream processing utilities for ReconForge.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator


def load_wordlist(file_path: str | Path | None = None, fallback: list[str] | None = None) -> list[str]:
    """
    Load words from a file path, stripping whitespace and comments.
    Falls back to a default list if file doesn't exist or is None.
    """
    if file_path:
        p = Path(file_path)
        if p.is_file():
            try:
                words = []
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            words.append(line)
                return words
            except Exception:
                pass
    return fallback or []


def stream_wordlist(file_path: str | Path) -> Iterator[str]:
    """Iterate over wordlist lines without loading the whole file into RAM."""
    p = Path(file_path)
    if p.is_file():
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line
