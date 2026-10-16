"""
JSON Report Generator for ReconForge.
Produces a structured, machine-readable JSON report of all scan results.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from reconforge.core.models import ScanResult


class JSONReporter:
    """Generates a JSON report from scan results."""

    def __init__(self, result: ScanResult):
        self.result = result

    def generate(self) -> str:
        """Generate JSON string."""
        data = self.result.to_dict()
        return json.dumps(data, indent=2, default=str, ensure_ascii=False)

    def write(self, path: str) -> None:
        """Write JSON report to file."""
        content = self.generate()
        Path(path).write_text(content, encoding="utf-8")
