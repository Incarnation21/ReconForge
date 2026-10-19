"""
Real-time Alerting and Webhook Dispatcher for ReconForge.
Supports Discord, Slack, Telegram, and Generic JSON Webhooks.
Sends instant notifications on high-severity findings and scan completion.
Default configuration includes pre-configured Telegram Bot (@ReconForgeBot).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.parse
from typing import Any, Optional

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from reconforge.core.models import Finding, ScanResult, Severity

def _load_env_file(path: str = ".env") -> None:
    """Load key-value environment variables from local .env file if present."""
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k and k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass

_load_env_file()

DEFAULT_CHAT_ID_FILE = ".telegram_chat_id"


class WebhookNotifier:
    """Dispatches real-time alerts to Discord, Slack, Telegram, or generic webhooks."""

    def __init__(
        self,
        url: Optional[str] = None,
        telegram_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
    ):
        self.url = url or os.environ.get("RECONFORGE_WEBHOOK") or os.environ.get("DISCORD_WEBHOOK_URL") or os.environ.get("SLACK_WEBHOOK_URL")
        
        # Load chat_id from param -> env -> local cache file
        self.telegram_chat_id = telegram_chat_id or os.environ.get("TELEGRAM_CHAT_ID")
        if not self.telegram_chat_id and os.path.exists(DEFAULT_CHAT_ID_FILE):
            try:
                with open(DEFAULT_CHAT_ID_FILE, "r", encoding="utf-8") as f:
                    cached = f.read().strip()
                    if cached:
                        self.telegram_chat_id = cached
            except Exception:
                pass

        # Parse telegram format from url:
        # e.g. "telegram" or "telegram:<chat_id>" or "telegram:<token>:<chat_id>"
        self.telegram_token = telegram_token or os.environ.get("TELEGRAM_BOT_TOKEN")
        if self.url:
            if self.url.lower() == "telegram":
                self.url = None
                self.telegram_token = self.telegram_token or os.environ.get("TELEGRAM_BOT_TOKEN")
            elif self.url.startswith("telegram:"):
                parts = self.url.split(":")
                if len(parts) == 2:
                    # telegram:<chat_id>
                    self.telegram_token = self.telegram_token or os.environ.get("TELEGRAM_BOT_TOKEN")
                    self.telegram_chat_id = parts[1]
                elif len(parts) >= 3:
                    # telegram:<token>:<chat_id>
                    self.telegram_token = parts[1]
                    self.telegram_chat_id = parts[2]
                self.url = None

        self.service_type = self._detect_service()

    def is_configured(self) -> bool:
        return bool(self.url or self.telegram_token)

    def _detect_service(self) -> str:
        if self.url:
            lower = self.url.lower()
            if "discord.com/api/webhooks" in lower:
                return "discord"
            elif "hooks.slack.com" in lower:
                return "slack"
            return "generic"
        elif self.telegram_token:
            return "telegram"
        return "disabled"

    async def _resolve_telegram_chat_id(self) -> Optional[str]:
        """Auto-detect chat ID by querying getUpdates if user started @ReconForgeBot."""
        if self.telegram_chat_id:
            return self.telegram_chat_id

        if not AIOHTTP_AVAILABLE or not self.telegram_token:
            return None

        url = f"https://api.telegram.org/bot{self.telegram_token}/getUpdates"
        try:
            timeout = aiohttp.ClientTimeout(total=5.0)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        updates = data.get("result", [])
                        if updates:
                            for upd in reversed(updates):
                                chat = upd.get("message", {}).get("chat", {}) or upd.get("my_chat_member", {}).get("chat", {})
                                cid = str(chat.get("id", ""))
                                if cid:
                                    self.telegram_chat_id = cid
                                    try:
                                        with open(DEFAULT_CHAT_ID_FILE, "w", encoding="utf-8") as f:
                                            f.write(cid)
                                    except Exception:
                                        pass
                                    return cid
        except Exception as e:
            logger.debug(f"Could not auto-resolve Telegram chat ID: {e}")
        return None

    async def send_finding_alert(self, finding: Finding) -> bool:
        """Send an urgent push alert for a high/critical security finding."""
        if not self.is_configured():
            return False

        if finding.severity not in (Severity.CRITICAL, Severity.HIGH):
            return False

        try:
            if self.service_type == "discord":
                payload = self._build_discord_finding_payload(finding)
                return await self._post_json(self.url, payload)
            elif self.service_type == "slack":
                payload = self._build_slack_finding_payload(finding)
                return await self._post_json(self.url, payload)
            elif self.service_type == "telegram":
                text = self._build_telegram_finding_text(finding)
                return await self._send_telegram(text)
            else:
                payload = {
                    "event": "finding_alert",
                    "finding": finding.to_dict(),
                }
                return await self._post_json(self.url, payload)
        except Exception as e:
            logger.warning(f"Failed to dispatch finding alert to webhook: {e}")
            return False

    async def send_scan_completed(
        self, result: ScanResult, diff_summary: Optional[str] = None
    ) -> bool:
        """Send a comprehensive scan completion summary."""
        if not self.is_configured():
            return False

        try:
            if self.service_type == "discord":
                payload = self._build_discord_completed_payload(result, diff_summary)
                return await self._post_json(self.url, payload)
            elif self.service_type == "slack":
                payload = self._build_slack_completed_payload(result, diff_summary)
                return await self._post_json(self.url, payload)
            elif self.service_type == "telegram":
                text = self._build_telegram_completed_text(result, diff_summary)
                return await self._send_telegram(text)
            else:
                payload = {
                    "event": "scan_completed",
                    "scan_id": result.scan_id,
                    "target": result.target,
                    "summary": result.to_dict()["summary"],
                    "diff": diff_summary,
                }
                return await self._post_json(self.url, payload)
        except Exception as e:
            logger.warning(f"Failed to dispatch scan completion to webhook: {e}")
            return False

    async def send_test_message(self, target: str = "Test-Target") -> bool:
        """Dispatch a test notification to verify end-to-end connectivity."""
        if self.service_type == "telegram":
            text = (
                "🚀 <b>ReconForge Alert System Online!</b>\n"
                "• <b>Status:</b> Connected & Operational\n"
                "• <b>Bot:</b> @ReconForgeBot\n"
                f"• <b>Target:</b> <code>{target}</code>\n"
                "• <b>Channel:</b> Telegram Push Notifications"
            )
            return await self._send_telegram(text)
        elif self.service_type == "discord":
            payload = {
                "username": "ReconForge Engine",
                "embeds": [
                    {
                        "title": "🚀 ReconForge Webhook Test",
                        "description": "Discord webhook connectivity verified successfully.",
                        "color": 0x2ECC71,
                    }
                ],
            }
            return await self._post_json(self.url, payload)
        elif self.service_type == "slack":
            return await self._post_json(self.url, {"text": "🚀 ReconForge Webhook Test: Slack connection successful!"})
        else:
            return await self._post_json(self.url, {"event": "test_ping", "status": "ok"})

    # ─────────────────────────────────────────────────────────────────────────
    # Discord Formatters
    # ─────────────────────────────────────────────────────────────────────────
    def _build_discord_finding_payload(self, finding: Finding) -> dict[str, Any]:
        color = 0xE74C3C if finding.severity == Severity.CRITICAL else 0xE67E22
        fields = [
            {"name": "Target", "value": finding.target, "inline": True},
            {"name": "Severity", "value": finding.severity.value.upper(), "inline": True},
            {"name": "Module", "value": finding.module, "inline": True},
        ]
        if finding.cwe:
            fields.append({"name": "CWE", "value": finding.cwe, "inline": True})
        if finding.cvss:
            fields.append({"name": "CVSS", "value": str(finding.cvss), "inline": True})
        if finding.evidence:
            evidence_str = finding.evidence[:500] + ("..." if len(finding.evidence) > 500 else "")
            fields.append({"name": "Evidence", "value": f"```{evidence_str}```", "inline": False})

        return {
            "username": "ReconForge Alert",
            "embeds": [
                {
                    "title": f"🚨 {finding.title}",
                    "description": finding.description[:1000],
                    "color": color,
                    "fields": fields,
                    "footer": {"text": "ReconForge Threat Intelligence"},
                }
            ],
        }

    def _build_discord_completed_payload(
        self, result: ScanResult, diff_summary: Optional[str]
    ) -> dict[str, Any]:
        summary = result.to_dict()["summary"]
        by_sev = summary.get("findings_by_severity", {})
        duration = round(result.duration_seconds() or 0, 1)

        fields = [
            {"name": "🎯 Target", "value": result.target, "inline": True},
            {"name": "⏱ Duration", "value": f"{duration}s", "inline": True},
            {"name": "🖥 Discovered Hosts", "value": str(summary.get("total_hosts", 0)), "inline": True},
            {"name": "🔌 Open Ports", "value": str(summary.get("total_open_ports", 0)), "inline": True},
            {"name": "🌐 Web Services", "value": str(summary.get("total_web_services", 0)), "inline": True},
            {
                "name": "🛡 Vulnerabilities",
                "value": (
                    f"Crit: `{by_sev.get('critical',0)}` | "
                    f"High: `{by_sev.get('high',0)}` | "
                    f"Med: `{by_sev.get('medium',0)}` | "
                    f"Low: `{by_sev.get('low',0)}`"
                ),
                "inline": False,
            },
        ]

        if diff_summary:
            fields.append({
                "name": "📊 Delta / Continuous Diff",
                "value": f"```{diff_summary[:800]}```",
                "inline": False,
            })

        return {
            "username": "ReconForge Engine",
            "embeds": [
                {
                    "title": f"Scan Complete: {result.target}",
                    "description": f"Scan ID: `{result.scan_id}` completed successfully.",
                    "color": 0x2ECC71 if summary.get("total_findings", 0) == 0 else 0x3498DB,
                    "fields": fields,
                    "footer": {"text": "ReconForge Automated Security Platform"},
                }
            ],
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Slack Formatters
    # ─────────────────────────────────────────────────────────────────────────
    def _build_slack_finding_payload(self, finding: Finding) -> dict[str, Any]:
        color = "danger" if finding.severity == Severity.CRITICAL else "warning"
        return {
            "text": f"🚨 *[ReconForge Alert]* {finding.title}",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {"title": "Target", "value": finding.target, "short": True},
                        {"title": "Severity", "value": finding.severity.value.upper(), "short": True},
                        {"title": "Description", "value": finding.description, "short": False},
                        {"title": "Evidence", "value": finding.evidence or "None", "short": False},
                    ],
                }
            ],
        }

    def _build_slack_completed_payload(
        self, result: ScanResult, diff_summary: Optional[str]
    ) -> dict[str, Any]:
        summary = result.to_dict()["summary"]
        by_sev = summary.get("findings_by_severity", {})
        text = (
            f"✅ *ReconForge Scan Completed: {result.target}*\n"
            f"• *Hosts*: {summary.get('total_hosts', 0)} | *Open Ports*: {summary.get('total_open_ports', 0)} | *Web Services*: {summary.get('total_web_services', 0)}\n"
            f"• *Findings*: Critical: {by_sev.get('critical',0)}, High: {by_sev.get('high',0)}, Med: {by_sev.get('medium',0)}\n"
        )
        if diff_summary:
            text += f"\n*State Diff:*\n```{diff_summary[:600]}```"
        return {"text": text}

    # ─────────────────────────────────────────────────────────────────────────
    # Telegram Formatters
    # ─────────────────────────────────────────────────────────────────────────
    def _build_telegram_finding_text(self, finding: Finding) -> str:
        return (
            f"🚨 <b>ReconForge Alert: {finding.severity.value.upper()}</b>\n"
            f"<b>Title:</b> {finding.title}\n"
            f"<b>Target:</b> <code>{finding.target}</code>\n"
            f"<b>Description:</b> {finding.description}\n"
            f"<b>CWE:</b> {finding.cwe or 'N/A'}"
        )

    def _build_telegram_completed_text(
        self, result: ScanResult, diff_summary: Optional[str]
    ) -> str:
        summary = result.to_dict()["summary"]
        by_sev = summary.get("findings_by_severity", {})
        msg = (
            f"✅ <b>ReconForge Scan Complete</b>\n"
            f"<b>Target:</b> <code>{result.target}</code>\n"
            f"<b>Hosts Discovered:</b> {summary.get('total_hosts', 0)}\n"
            f"<b>Open Ports:</b> {summary.get('total_open_ports', 0)}\n"
            f"<b>Total Findings:</b> {summary.get('total_findings', 0)} (Crit: {by_sev.get('critical',0)}, High: {by_sev.get('high',0)})\n"
        )
        if diff_summary:
            msg += f"\n<b>Delta Diff:</b>\n<pre>{diff_summary[:500]}</pre>"
        return msg

    # ─────────────────────────────────────────────────────────────────────────
    # Transport Dispatchers
    # ─────────────────────────────────────────────────────────────────────────
    async def _post_json(self, url: str, payload: dict[str, Any]) -> bool:
        if not AIOHTTP_AVAILABLE:
            return False
        timeout = aiohttp.ClientTimeout(total=8.0)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload) as resp:
                return resp.status in (200, 204)

    async def _send_telegram(self, text: str) -> bool:
        if not AIOHTTP_AVAILABLE or not self.telegram_token:
            return False
        
        # Ensure chat_id is resolved
        if not self.telegram_chat_id:
            await self._resolve_telegram_chat_id()

        if not self.telegram_chat_id:
            logger.warning(
                "Telegram alert skipped: Chat ID not set. "
                "Open https://t.me/ReconForgeBot on Telegram, tap 'Start', and re-run."
            )
            return False

        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        return await self._post_json(url, payload)
