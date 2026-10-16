"""
ReconForge Command-Line Interface.
Supports:
  reconforge scan <target> [options]
  reconforge list-modules
  reconforge report <results.json> --format html
  reconforge <target> --authorized (shorthand)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from reconforge.core.context import ScanConfig, ScanContext
from reconforge.core.models import ScanResult
from reconforge.core.module import get_registry
from reconforge.core.orchestrator import Orchestrator
from reconforge.core.scope import normalize_target, ScopeViolationError
from reconforge.reporting.json_report import JSONReporter
from reconforge.reporting.html_report import HTMLReporter

BANNER = r"""
 ____                      _____                      
|  _ \ ___  ___ ___  _ __|  ___|__  _ __ __ _  ___  
| |_) / _ \/ __/ _ \| '_ \ |_ / _ \| '__/ _` |/ _ \ 
|  _ <  __/ (_| (_) | | | |  _| (_) | | | (_| |  __/ 
|_| \_\___|\___\___/|_| |_|_|  \___/|_|  \__, |\___| 
                                          |___/        
Modular Reconnaissance Framework v1.0
For authorized security testing only.
"""


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, handlers=[logging.StreamHandler(sys.stdout)])
    for noisy in ("urllib3", "asyncio", "aiohttp", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def print_banner(no_color: bool = False) -> None:
    if no_color:
        print(BANNER)
    else:
        print(f"\033[92m{BANNER}\033[0m")


def list_modules_cmd() -> int:
    """Print all available registered modules."""
    # Ensure modules are imported
    from reconforge.modules import (
        dns_enum, subdomain, ip_resolve, portscan,
        http_probe, tech_fingerprint, dir_enum, tls_inspect, whois_rdap
    )
    registry = get_registry()
    print("\nAvailable ReconForge Modules:")
    print("=" * 65)
    print(f"{'Module Name':<20} {'Requires':<15} {'Provides':<20}")
    print("-" * 65)
    for name, cls in sorted(registry.items()):
        req = ", ".join(cls.REQUIRES) if cls.REQUIRES else "none"
        prov = ", ".join(cls.PROVIDES) if cls.PROVIDES else "none"
        print(f"{name:<20} {req:<15} {prov:<20}")
        if cls.DESCRIPTION:
            print(f"  |-- {cls.DESCRIPTION}")
    print("=" * 65 + "\n")
    return 0


def report_cmd(json_file: str, output_format: str = "html", output_file: str | None = None) -> int:
    """Re-render HTML report from a saved results.json file without rescanning."""
    if not os.path.exists(json_file):
        print(f"[ERROR] Result file not found: {json_file}", file=sys.stderr)
        return 1

    try:
        reporter = HTMLReporter.from_json_file(json_file)
        out_path = output_file or json_file.replace(".json", ".html")
        if not out_path.endswith(".html"):
            out_path += ".html"
        reporter.write(out_path)
        print(f"[+] Successfully rendered HTML report: {out_path}")
        return 0
    except Exception as e:
        print(f"[ERROR] Failed to generate report: {e}", file=sys.stderr)
        return 1


async def scan_target(args: argparse.Namespace) -> int:
    is_auth = getattr(args, "authorized", False) or os.environ.get("RECONFORGE_AUTHORIZED") == "1"
    if not is_auth:
        print(
            "\n[!] ERROR: Authorization required.\n"
            "    You must specify --authorized (or set RECONFORGE_AUTHORIZED=1) to confirm you have\n"
            "    explicit written permission to scan the target.\n",
            file=sys.stderr,
        )
        return 2

    # Parse target
    try:
        target = normalize_target(args.target)
    except Exception as e:
        print(f"[ERROR] Invalid target '{args.target}': {e}", file=sys.stderr)
        return 1

    config = ScanConfig(
        authorized=True,
        scope_file=args.scope_file,
        allow_private=args.allow_private,
        modules=args.modules or [],
        skip_modules=args.skip_modules or [],
        rate=args.rate,
        concurrency=args.concurrency,
        timeout=args.timeout,
        ports=args.ports,
        use_nmap=args.nmap,
        wordlist=args.wordlist,
        dir_wordlist=args.dir_wordlist,
        output_dir=args.output_dir,
        output_format=args.format,
        verbose=args.verbose,
        no_color=args.no_color,
    )

    scan_id = uuid.uuid4().hex[:8]
    scan_result = ScanResult(
        target=args.target,
        scan_id=scan_id,
        metadata={
            "tool": "reconforge",
            "version": "1.0.0",
            "operator": os.environ.get("USER", os.environ.get("USERNAME", "analyst")),
            "authorized": True,
        },
    )

    ctx = ScanContext(target=target, config=config, scan_result=scan_result)

    # Validate scope
    try:
        ctx.scope.validate(target.domain or target.ip or target.raw)
    except ScopeViolationError as e:
        print(f"\n[SCOPE VIOLATION] {e}\n", file=sys.stderr)
        return 1

    logger = logging.getLogger("reconforge.cli")
    logger.info(f"Scan initialized | ID: {scan_id} | Target: {target.raw} ({target.type.value})")

    interrupted = False
    try:
        orchestrator = Orchestrator(ctx)
        result = await orchestrator.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.warning("\n[!] Scan interrupted by user. Generating partial report...")
        result = ctx.store.result
        result.end_time = datetime.now(timezone.utc)
        result.metadata["interrupted"] = True
        interrupted = True

    # Generate reports
    os.makedirs(args.output_dir, exist_ok=True)
    clean_target = target.raw.replace("/", "_").replace(":", "_").replace("?", "_")
    base_name = f"reconforge_{clean_target}_{scan_id}"

    if "json" in args.format:
        json_path = os.path.join(args.output_dir, f"{base_name}.json")
        JSONReporter(result).write(json_path)
        logger.info(f"Saved JSON report: {json_path}")

    if "html" in args.format:
        html_path = os.path.join(args.output_dir, f"{base_name}.html")
        HTMLReporter(result).write(html_path)
        logger.info(f"Saved HTML report: {html_path}")

    summary = result.to_dict()["summary"]
    print(f"\n{'='*60}")
    print(f"  RECONFORGE SCAN COMPLETE: {result.target}")
    print(f"{'='*60}")
    print(f"  Discovered Hosts : {summary['total_hosts']}")
    print(f"  Open Ports       : {summary['total_open_ports']}")
    print(f"  Web Services     : {summary['total_web_services']}")
    print(f"  Total Findings   : {summary['total_findings']}")
    by_sev = summary.get("findings_by_severity", {})
    print(f"  Severities       : Crit:{by_sev.get('critical',0)} High:{by_sev.get('high',0)} Med:{by_sev.get('medium',0)} Low:{by_sev.get('low',0)}")
    print(f"{'='*60}\n")

    if interrupted:
        return 130
    return 0


def main() -> None:
    # First check if the first argument is a subcommand
    if len(sys.argv) > 1 and sys.argv[1] == "list-modules":
        sys.exit(list_modules_cmd())

    parser = argparse.ArgumentParser(
        prog="reconforge",
        description="ReconForge - Modular Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to run")

    # --- scan subcommand ---
    scan_parser = subparsers.add_parser("scan", help="Run reconnaissance pipeline against a target")
    for p in (scan_parser,):
        p.add_argument("target", metavar="TARGET", help="Target: domain, IP, CIDR, or URL")
        p.add_argument("--authorized", action="store_true", help="Confirm authorization")
        p.add_argument("--scope-file", metavar="FILE", help="In-scope domains/CIDRs")
        p.add_argument("--allow-private", action="store_true", help="Allow private RFC1918 ranges")
        p.add_argument("--modules", "-m", nargs="+", help="Modules to run")
        p.add_argument("--skip-modules", nargs="+", default=[], help="Modules to skip")
        p.add_argument("--rate", type=float, default=100.0, help="Requests/sec rate limit")
        p.add_argument("--concurrency", type=int, default=200, help="Max concurrency")
        p.add_argument("--timeout", type=float, default=5.0, help="Timeout in seconds")
        p.add_argument("--ports", default="top1000", help="Port profile: top100, top1000, all, or custom")
        p.add_argument("--nmap", action="store_true", help="Enable Nmap secondary engine")
        p.add_argument("--wordlist", "-w", help="Subdomain wordlist")
        p.add_argument("--dir-wordlist", help="Directory wordlist")
        p.add_argument("--output-dir", "-o", default=".", help="Report directory")
        p.add_argument("--format", "-f", nargs="+", choices=["json", "html"], default=["json", "html"])
        p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
        p.add_argument("--no-color", action="store_true", help="Disable color")

    # --- list-modules subcommand ---
    subparsers.add_parser("list-modules", help="List all registered recon modules")

    # --- report subcommand ---
    report_parser = subparsers.add_parser("report", help="Re-render HTML report from results.json")
    report_parser.add_argument("json_file", metavar="JSON_FILE", help="Path to results.json file")
    report_parser.add_argument("--format", default="html", choices=["html"], help="Output format")
    report_parser.add_argument("-o", "--output", help="Output file path")

    # Direct shorthand fallback: reconforge <target> [flags]
    if len(sys.argv) > 1 and sys.argv[1] not in ("scan", "list-modules", "report", "-h", "--help"):
        # Insert "scan" as default subcommand
        sys.argv.insert(1, "scan")

    args = parser.parse_args()

    if args.subcommand == "list-modules":
        sys.exit(list_modules_cmd())
    elif args.subcommand == "report":
        sys.exit(report_cmd(args.json_file, args.format, args.output))
    elif args.subcommand == "scan":
        setup_logging(args.verbose)
        print_banner(args.no_color)
        sys.exit(asyncio.run(scan_target(args)))
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
