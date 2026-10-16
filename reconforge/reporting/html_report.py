"""
HTML Report Generator for ReconForge.
Produces a self-contained, interactive HTML report with Jinja2 templating,
dark mode, severity badges, and filtering.
"""
from __future__ import annotations

import html
import json
import os
from pathlib import Path
from typing import Any

from reconforge.core.models import ScanResult

try:
    import jinja2
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False


class HTMLReporter:
    """Generates a self-contained HTML report from scan results."""

    def __init__(self, result: ScanResult | dict[str, Any]):
        if isinstance(result, ScanResult):
            self.data = result.to_dict()
        else:
            self.data = result

    def generate(self) -> str:
        """Render using Jinja2 template if available, else embedded generator."""
        template_dir = Path(__file__).parent / "templates"
        template_file = template_dir / "report.html.j2"

        if JINJA_AVAILABLE and template_file.is_file():
            try:
                env = jinja2.Environment(
                    loader=jinja2.FileSystemLoader(str(template_dir)),
                    autoescape=jinja2.select_autoescape(["html", "xml", "j2"]),
                )
                template = env.get_template("report.html.j2")
                
                # Normalize keys for template
                target_data = self.data.get("target", {})
                if isinstance(target_data, str):
                    target_data = {"raw": target_data, "kind": "domain", "host": target_data}

                meta_data = self.data.get("metadata", {})
                meta_data.setdefault("started", self.data.get("start_time", ""))
                meta_data.setdefault("duration_s", self.data.get("duration_seconds", 0))
                meta_data.setdefault("interrupted", False)

                summary = self.data.get("summary", {})
                findings = self.data.get("findings", [])
                
                # Transform hosts into results structure for template
                results = {"ips": [], "ports": [], "http": [], "tech": []}
                for hostname, h in self.data.get("hosts", {}).items():
                    results["ips"].extend(h.get("ip_addresses", []))
                    for p in h.get("open_ports", []):
                        p_entry = dict(p)
                        p_entry["host"] = hostname
                        results["ports"].append(p_entry)
                    host_techs = h.get("technologies", [])
                    results["tech"].extend(host_techs)
                    for s in h.get("http_services", []):
                        s_entry = dict(s)
                        s_entry["host"] = hostname
                        if not s_entry.get("technologies"):
                            s_entry["technologies"] = host_techs
                        results["http"].append(s_entry)

                return template.render(
                    target=target_data,
                    meta=meta_data,
                    summary=summary,
                    findings=findings,
                    results=results,
                )
            except Exception as e:
                pass

        return self._generate_fallback()

    def _generate_fallback(self) -> str:
        data = self.data
        summary = data.get("summary", {})
        hosts = data.get("hosts", {})
        findings = sorted(
            data.get("findings", []),
            key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.get("severity", "info")),
        )
        target_str = data.get("target", "")
        if isinstance(target_str, dict):
            target_str = target_str.get("raw", "")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconForge Report - {html.escape(str(target_str))}</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #238636;
    --critical: #ff3b3b; --high: #ff6b35; --medium: #ffc107;
    --low: #17a2b8; --info: #6c757d;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.6; padding: 20px; }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  .header {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
             padding: 24px; margin-bottom: 20px; }}
  .header h1 {{ font-size: 24px; color: #58a6ff; }}
  .header .meta {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }}
  .stat-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-card .num {{ font-size: 32px; font-weight: 700; }}
  .stat-card .label {{ color: var(--muted); font-size: 12px; }}
  .critical .num {{ color: var(--critical); }}
  .high .num {{ color: var(--high); }}
  .medium .num {{ color: var(--medium); }}
  .low .num {{ color: var(--low); }}
  .section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
              padding: 20px; margin-bottom: 20px; }}
  .section h2 {{ font-size: 16px; margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .badge-critical {{ background: var(--critical); color: #fff; }}
  .badge-high {{ background: var(--high); color: #fff; }}
  .badge-medium {{ background: var(--medium); color: #222; }}
  .badge-low {{ background: var(--low); color: #fff; }}
  .badge-info {{ background: var(--info); color: #fff; }}
  .finding {{ border: 1px solid var(--border); border-radius: 6px; margin-bottom: 10px; overflow: hidden; }}
  .finding-header {{ padding: 12px 16px; cursor: pointer; display: flex; align-items: center; gap: 10px;
                     background: rgba(255,255,255,0.02); user-select: none; }}
  .finding-body {{ padding: 16px; border-top: 1px solid var(--border); font-size: 13px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px 12px; color: var(--muted); border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid rgba(48,54,61,0.5); vertical-align: top; }}
  .tag {{ display: inline-block; background: rgba(88,166,255,0.15); color: #58a6ff; padding: 1px 6px; border-radius: 3px; font-size: 11px; margin: 1px; }}
  .open-port {{ display: inline-block; background: rgba(35,134,54,0.2); color: #3fb950; padding: 2px 8px; border-radius: 3px; font-size: 12px; margin: 2px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>ReconForge Reconnaissance Report</h1>
    <div class="meta">
      Target: <strong>{html.escape(str(target_str))}</strong> &nbsp;|&nbsp;
      Scan ID: <code>{html.escape(str(data.get('scan_id', '')))}</code> &nbsp;|&nbsp;
      Duration: {html.escape(str(round(data.get('duration_seconds', 0) or 0, 1)))}s
    </div>
  </div>

  <div class="grid">
    <div class="stat-card"><div class="num">{summary.get('total_hosts', len(hosts))}</div><div class="label">Hosts</div></div>
    <div class="stat-card"><div class="num">{summary.get('total_open_ports', 0)}</div><div class="label">Open Ports</div></div>
    <div class="stat-card"><div class="num">{summary.get('total_web_services', 0)}</div><div class="label">Web Services</div></div>
    <div class="stat-card"><div class="num">{len(findings)}</div><div class="label">Total Findings</div></div>
  </div>

  <div class="section">
    <h2>Security Findings ({len(findings)})</h2>
    {''.join(f"""
    <div class="finding">
      <div class="finding-header">
        <span class="badge badge-{f.get('severity', 'info')}">{f.get('severity', 'info').upper()}</span>
        <strong style="margin-left: 10px;">{html.escape(str(f.get('title', '')))}</strong>
        <span style="color:var(--muted); margin-left:auto;">{html.escape(str(f.get('target', '')))}</span>
      </div>
      <div class="finding-body">
        <div>{html.escape(str(f.get('description', '')))}</div>
        {f"<pre style='margin-top:8px;'>{html.escape(str(f.get('evidence', '')))}</pre>" if f.get('evidence') else ''}
      </div>
    </div>
    """ for f in findings) if findings else "<p style='color:var(--muted);'>No findings recorded.</p>"}
  </div>

  <div class="section">
    <h2>Discovered Hosts ({len(hosts)})</h2>
    <table>
      <thead><tr><th>Hostname</th><th>IPs</th><th>Ports</th><th>Technologies</th></tr></thead>
      <tbody>
        {''.join(f"""
        <tr>
          <td><strong>{html.escape(str(name))}</strong></td>
          <td>{html.escape(', '.join(h.get('ip_addresses', [])))}</td>
          <td>{' '.join(f'<span class="open-port">{p.get("port")}/{p.get("protocol","tcp")}</span>' for p in h.get('open_ports', [])) or '—'}</td>
          <td>{' '.join(f'<span class="tag">{html.escape(t)}</span>' for t in h.get('technologies', [])) or '—'}</td>
        </tr>
        """ for name, h in hosts.items())}
      </tbody>
    </table>
  </div>
</div>
</body>
</html>"""

    def write(self, path: str) -> None:
        """Write HTML report to file."""
        content = self.generate()
        Path(path).write_text(content, encoding="utf-8")

    @classmethod
    def from_json_file(cls, json_path: str) -> "HTMLReporter":
        """Load from a results.json file and re-render without rescanning."""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(data)
