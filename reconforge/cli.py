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
from reconforge.core.diff_engine import DiffEngine, StateDatabase
from reconforge.core.models import ScanResult, Severity
from reconforge.core.module import get_registry
from reconforge.core.orchestrator import Orchestrator
from reconforge.core.scope import normalize_target, ScopeViolationError
from reconforge.reporting.json_report import JSONReporter
from reconforge.reporting.html_report import HTMLReporter
from reconforge.reporting.webhook import WebhookNotifier

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
        http_probe, tech_fingerprint, dir_enum, tls_inspect, whois_rdap, takeover
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


def diff_cmd(args: argparse.Namespace) -> int:
    """Compute and display diff between historical scans or list scans."""
    db_path = getattr(args, "db_path", None) or os.path.join(".", "reconforge_history.db")
    if not os.path.exists(db_path):
        print(f"[*] No history database found at {db_path}. Run a scan first.")
        return 0

    db = StateDatabase(db_path)

    if getattr(args, "list", False):
        scans = db.list_all_scans()
        if not scans:
            print(f"[*] No scans found in database: {db_path}")
            return 0
        print("\nHistorical ReconForge Scans:")
        print("=" * 85)
        print(f"{'Scan ID':<12} {'Target':<28} {'Date / Time':<22} {'Hosts':<7} {'Ports':<7} {'Findings':<8}")
        print("-" * 85)
        for s in scans:
            start_fmt = str(s.get("start_time", ""))[:19].replace("T", " ")
            print(f"{s.get('scan_id',''):<12} {s.get('target',''):<28} {start_fmt:<22} {s.get('total_hosts',0):<7} {s.get('total_open_ports',0):<7} {s.get('total_findings',0):<8}")
        print("=" * 85 + "\n")
        return 0

    if getattr(args, "target", None):
        target = args.target
        recent = db.get_latest_scans_for_target(target, limit=2)
        if not recent:
            print(f"[!] No scans found for target '{target}' in database {db_path}", file=sys.stderr)
            return 1
        if len(recent) == 1:
            print(f"[*] Only 1 scan found for '{target}' ({recent[0].get('scan_id')}). Displaying baseline...")
            delta = DiffEngine.compute(None, recent[0])
        else:
            delta = DiffEngine.compute(recent[1], recent[0])
        print(delta.to_summary_text())
        return 0

    scan_ids = getattr(args, "scan_ids", []) or []
    if len(scan_ids) >= 2:
        s1 = db.get_scan(scan_ids[0])
        s2 = db.get_scan(scan_ids[1])
        if not s1 or not s2:
            print(f"[!] One or both scan IDs not found in database {db_path}", file=sys.stderr)
            return 1
        delta = DiffEngine.compute(s1, s2)
        print(delta.to_summary_text())
        return 0
    elif len(scan_ids) == 1:
        s = db.get_scan(scan_ids[0])
        if not s:
            print(f"[!] Scan ID '{scan_ids[0]}' not found.", file=sys.stderr)
            return 1
        recent = db.get_latest_scans_for_target(s["target"], limit=10)
        prev = None
        for idx, item in enumerate(recent):
            if item["scan_id"] == s["scan_id"] and idx + 1 < len(recent):
                prev = recent[idx + 1]
                break
        delta = DiffEngine.compute(prev, s)
        print(delta.to_summary_text())
    else:
        print("[!] Please specify --target <domain>, provide scan IDs to compare, or use --list.")
        return 1


async def test_telegram_cmd(chat_id: str | None = None) -> int:
    """Verify Telegram bot connectivity and auto-detect chat ID."""
    notifier = WebhookNotifier(telegram_chat_id=chat_id)
    if not notifier.telegram_token:
        print(
            "\n[!] ERROR: TELEGRAM_BOT_TOKEN not configured.\n"
            "    Please define TELEGRAM_BOT_TOKEN in your .env file or environment variable.\n"
            "    See .env.example for details.\n",
            file=sys.stderr,
        )
        return 1

    print("\n" + "=" * 60)
    print("  RECONFORGE TELEGRAM BOT TEST")
    print("=" * 60)
    print(f"  Bot Token  : {notifier.telegram_token[:10]}...{notifier.telegram_token[-6:]}")
    
    import urllib.request
    try:
        req = urllib.request.urlopen(f"https://api.telegram.org/bot{notifier.telegram_token}/getMe", timeout=5)
        bot_info = json.loads(req.read().decode())["result"]
        bot_username = bot_info.get("username", "ReconForgeBot")
        print(f"  Bot Name   : {bot_info.get('first_name')} (@{bot_username})")
        print("  Connection : [OK] Online and Verified")
    except Exception as e:
        print(f"  [ERROR] Failed to reach Telegram API: {e}", file=sys.stderr)
        return 1

    cid = await notifier._resolve_telegram_chat_id()
    if not cid:
        print("\n[!] ACTION REQUIRED: Chat ID not yet detected.")
        print(f"    1. Open your Telegram app and search for: @{bot_username}")
        print(f"       or click: https://t.me/{bot_username}")
        print("    2. Tap 'START' (or send /start)")
        print("    3. Re-run: reconforge test-telegram\n")
        return 1

    print(f"  Chat ID    : {cid}")
    print("[*] Dispatching test notification to your Telegram...")
    success = await notifier.send_test_message(target="reconforge-init")
    if success:
        print("[+] SUCCESS! Test alert received on Telegram.\n" + "=" * 60 + "\n")
        return 0
    else:
        print("[!] Failed to send message. Please ensure you have tapped START on the bot.\n")
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
        webhook=getattr(args, "webhook", None),
        db_path=getattr(args, "db_path", None),
        enable_diff=getattr(args, "diff", False),
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

    # SQLite state tracking & optional continuous monitoring diff
    db_path = getattr(args, "db_path", None) or os.path.join(args.output_dir, "reconforge_history.db")
    db = StateDatabase(db_path)

    diff_summary: str | None = None
    if getattr(args, "diff", False):
        recent_scans = db.get_latest_scans_for_target(result.target, limit=1)
        prev_scan = recent_scans[0] if recent_scans else None
        delta = DiffEngine.compute(prev_scan, result.to_dict())
        diff_summary = delta.to_summary_text()
        print("\n" + diff_summary)

    db.save_scan(result)

    # Real-time Webhook Alerts
    webhook_url = getattr(args, "webhook", None)
    notifier = WebhookNotifier(url=webhook_url)
    if notifier.is_configured():
        logger.info(f"Dispatching notifications via webhook ({notifier.service_type})...")
        for f in result.findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                await notifier.send_finding_alert(f)
        await notifier.send_scan_completed(result, diff_summary=diff_summary)

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
        p.add_argument("--webhook", help="Webhook URL (Discord, Slack, or generic HTTP POST) for instant alerts")
        p.add_argument("--diff", action="store_true", help="Compare against previous scan for this target and display delta")
        p.add_argument("--db-path", help="Path to SQLite history database (defaults to <output_dir>/reconforge_history.db)")
        p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
        p.add_argument("--no-color", action="store_true", help="Disable color")

    # --- list-modules subcommand ---
    subparsers.add_parser("list-modules", help="List all registered recon modules")

    # --- report subcommand ---
    report_parser = subparsers.add_parser("report", help="Re-render HTML report from results.json")
    report_parser.add_argument("json_file", metavar="JSON_FILE", help="Path to results.json file")
    report_parser.add_argument("--format", default="html", choices=["html"], help="Output format")
    report_parser.add_argument("-o", "--output", help="Output file path")

    # --- diff subcommand ---
    diff_parser = subparsers.add_parser("diff", help="Compare historical scans and track asset deltas")
    diff_parser.add_argument("scan_ids", nargs="*", help="Optional scan IDs to compare (e.g. scan1 scan2)")
    diff_parser.add_argument("--target", "-t", help="Target domain/IP to compare the latest 2 scans")
    diff_parser.add_argument("--db-path", help="Path to SQLite history database")
    diff_parser.add_argument("--list", "-l", action="store_true", help="List all historical scans in the database")

    # --- test-telegram subcommand ---
    tt_parser = subparsers.add_parser("test-telegram", help="Test Telegram bot alert connection (@ReconForgeBot)")
    tt_parser.add_argument("--chat-id", "-c", help="Your Telegram Chat ID (optional, auto-detected)")

    # Direct shorthand fallback: reconforge <target> [flags]
    if len(sys.argv) > 1 and sys.argv[1] not in ("scan", "list-modules", "report", "diff", "test-telegram", "-h", "--help"):
        # Insert "scan" as default subcommand
        sys.argv.insert(1, "scan")

    args = parser.parse_args()

    if args.subcommand == "list-modules":
        sys.exit(list_modules_cmd())
    elif args.subcommand == "report":
        sys.exit(report_cmd(args.json_file, args.format, args.output))
    elif args.subcommand == "diff":
        sys.exit(diff_cmd(args))
    elif args.subcommand == "test-telegram":
        sys.exit(asyncio.run(test_telegram_cmd(getattr(args, "chat_id", None))))
    elif args.subcommand == "scan":
        setup_logging(args.verbose)
        print_banner(args.no_color)
        sys.exit(asyncio.run(scan_target(args)))
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()

