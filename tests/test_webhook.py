"""
Tests for Webhook Notifier.
Verifies payload construction for Discord, Slack, Telegram, and generic endpoints,
as well as severity filtering and fail-soft behavior.
"""
import pytest
from unittest.mock import AsyncMock, patch

from reconforge.core.models import Finding, ScanResult, Severity
from reconforge.reporting.webhook import WebhookNotifier


@pytest.fixture
def sample_finding():
    return Finding(
        id="TAKEOVER-test",
        title="Verified Subdomain Takeover: docs.example.com",
        severity=Severity.CRITICAL,
        description="Dangling CNAME pointer to unclaimed S3 bucket.",
        target="docs.example.com",
        module="takeover",
        evidence="CNAME: test.s3.amazonaws.com\nBody: NoSuchBucket",
        cwe="CWE-284: Improper Access Control",
        cvss=8.6,
    )


@pytest.fixture
def sample_scan_result():
    return ScanResult(
        target="example.com",
        scan_id="abc12345",
        metadata={"tool": "reconforge"},
    )


def test_service_detection():
    discord = WebhookNotifier(url="https://discord.com/api/webhooks/123/xyz")
    assert discord.service_type == "discord"

    slack = WebhookNotifier(url="https://hooks.slack.com/services/T00/B00/X00")
    assert slack.service_type == "slack"

    generic = WebhookNotifier(url="https://api.mycompany.com/webhook")
    assert generic.service_type == "generic"

    telegram = WebhookNotifier(url="telegram:mytoken:12345678")
    assert telegram.service_type == "telegram"
    assert telegram.telegram_token == "mytoken"
    assert telegram.telegram_chat_id == "12345678"


def test_discord_finding_payload(sample_finding):
    notifier = WebhookNotifier(url="https://discord.com/api/webhooks/test")
    payload = notifier._build_discord_finding_payload(sample_finding)

    assert "embeds" in payload
    embed = payload["embeds"][0]
    assert "Verified Subdomain Takeover" in embed["title"]
    assert embed["color"] == 0xE74C3C  # Red for critical
    field_names = [f["name"] for f in embed["fields"]]
    assert "Severity" in field_names
    assert "Target" in field_names
    assert "Evidence" in field_names


def test_slack_finding_payload(sample_finding):
    notifier = WebhookNotifier(url="https://hooks.slack.com/services/test")
    payload = notifier._build_slack_finding_payload(sample_finding)

    assert "attachments" in payload
    att = payload["attachments"][0]
    assert att["color"] == "danger"
    assert len(att["fields"]) >= 4


def test_telegram_formatting(sample_finding):
    notifier = WebhookNotifier(telegram_token="token", telegram_chat_id="chat")
    text = notifier._build_telegram_finding_text(sample_finding)

    assert "CRITICAL" in text
    assert "docs.example.com" in text
    assert "CWE-284" in text


@pytest.mark.asyncio
async def test_send_finding_ignores_low_severity():
    notifier = WebhookNotifier(url="https://discord.com/api/webhooks/test")
    low_finding = Finding(
        id="LOW-test",
        title="Info disclosure",
        severity=Severity.LOW,
        description="Minor info",
        target="example.com",
        module="test",
    )
    # Should return False immediately without making network calls
    sent = await notifier.send_finding_alert(low_finding)
    assert sent is False


@pytest.mark.asyncio
async def test_send_finding_alert_dispatches(sample_finding):
    notifier = WebhookNotifier(url="https://discord.com/api/webhooks/test")
    with patch.object(notifier, "_post_json", AsyncMock(return_value=True)) as mock_post:
        success = await notifier.send_finding_alert(sample_finding)
        assert success is True
        mock_post.assert_called_once()


@pytest.mark.asyncio
async def test_send_scan_completed(sample_scan_result):
    notifier = WebhookNotifier(url="https://discord.com/api/webhooks/test")
    with patch.object(notifier, "_post_json", AsyncMock(return_value=True)) as mock_post:
        success = await notifier.send_scan_completed(sample_scan_result, diff_summary="Delta: +1 host")
        assert success is True
        mock_post.assert_called_once()
