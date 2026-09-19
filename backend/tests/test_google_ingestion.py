"""
Unit tests for Google Workspace / Gmail Real-Time Ingestion and Mailbox Watch Manager
"""
import asyncio
import base64
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta

from app.services.google_ingestion import (
    GoogleIngestionService,
    MailboxWatchManager,
    google_ingestion_service,
    mailbox_watch_manager
)
from app.api.v1.threat_stream import ThreatStreamChannel, threat_stream_channel
from app.schemas import EmailAnalysisResponse


RAW_PHISHING_EMAIL = b"""From: security-alert@paypa1-security.com
To: victim@example.com
Subject: URGENT: Your PayPal Account Has Been Suspended
Date: Wed, 18 Sep 2024 12:00:00 +0000
Message-ID: <threat-12345@paypa1-security.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Customer,

Your account has been suspended due to suspicious activity.
Click here immediately: http://paypa1-update-login.com/verify?account=123
"""


@pytest.mark.asyncio
async def test_decode_raw_mime():
    """Test URL-safe base64 MIME decoding with and without padding"""
    original_bytes = RAW_PHISHING_EMAIL
    b64_str = base64.urlsafe_b64encode(original_bytes).decode("utf-8")

    # Test with standard padding
    decoded = GoogleIngestionService.decode_raw_mime(b64_str)
    assert decoded == original_bytes

    # Test without padding (strip '=')
    unpadded_b64 = b64_str.rstrip("=")
    decoded_unpadded = GoogleIngestionService.decode_raw_mime(unpadded_b64)
    assert decoded_unpadded == original_bytes


@pytest.mark.asyncio
async def test_fetch_and_analyze_message_with_mock_gmail():
    """
    Test that fetch_and_analyze_message:
    1. Fetches raw message using gmail.users().messages().get(userId=..., id=..., format='raw')
    2. Decodes raw bytes
    3. Passes decoded raw bytes to EmailAnalysisOrchestrator
    4. Pushes analysis results to WebSocket threat-stream
    """
    service = GoogleIngestionService()
    test_stream = ThreatStreamChannel()

    # Encode test raw MIME
    raw_b64 = base64.urlsafe_b64encode(RAW_PHISHING_EMAIL).decode("utf-8")

    # Mock Google Gmail API service
    mock_gmail_service = MagicMock()
    mock_messages = MagicMock()
    mock_get = MagicMock()
    mock_get.execute.return_value = {
        "id": "msg-9999",
        "threadId": "th-123",
        "raw": raw_b64
    }
    mock_messages.get.return_value = mock_get
    mock_gmail_service.users().messages.return_value = mock_messages

    # Mock WebSocket receiver
    mock_ws = AsyncMock()
    await test_stream.connect(mock_ws)

    with patch("app.services.google_ingestion.threat_stream_channel", test_stream):
        analysis = await service.fetch_and_analyze_message(
            user_email="victim@example.com",
            message_id="msg-9999",
            db=None,
            gmail_service=mock_gmail_service
        )

        # 1. Verify Gmail API was called with format='raw'
        mock_messages.get.assert_called_once_with(
            userId="victim@example.com",
            id="msg-9999",
            format="raw"
        )

        # 2. Verify analysis result
        assert isinstance(analysis, EmailAnalysisResponse)
        assert analysis.from_address == "security-alert@paypa1-security.com"
        assert "victim@example.com" in analysis.to_addresses
        assert analysis.subject == "URGENT: Your PayPal Account Has Been Suspended"
        assert analysis.risk_score > 0

        # 3. Verify broadcast occurred over WebSocket threat-stream
        assert mock_ws.send_text.called
        sent_payload = json.loads(mock_ws.send_text.call_args[0][0])
        assert sent_payload["type"] == "threat_analysis"
        assert sent_payload["data"]["email_id"] == analysis.email_id
        assert sent_payload["data"]["subject"] == analysis.subject


@pytest.mark.asyncio
async def test_process_history_notification_flow():
    """
    Test history notification processing:
    - Queries history list with startHistoryId
    - Retrieves message ID and triggers ingestion
    """
    service = GoogleIngestionService()
    user_email = "testuser@example.com"
    service._history_state[user_email] = 1000

    raw_b64 = base64.urlsafe_b64encode(RAW_PHISHING_EMAIL).decode("utf-8")

    mock_gmail = MagicMock()
    # Mock history list
    mock_history = MagicMock()
    mock_history_list = MagicMock()
    mock_history_list.execute.return_value = {
        "history": [
            {
                "id": "1001",
                "messagesAdded": [
                    {"message": {"id": "msg-hist-1"}}
                ]
            }
        ]
    }
    mock_history.list.return_value = mock_history_list
    mock_gmail.users().history.return_value = mock_history

    # Mock message get
    mock_messages = MagicMock()
    mock_get = MagicMock()
    mock_get.execute.return_value = {"id": "msg-hist-1", "raw": raw_b64}
    mock_messages.get.return_value = mock_get
    mock_gmail.users().messages.return_value = mock_messages

    results = await service.process_history_notification(
        user_email=user_email,
        history_id=1005,
        db=None,
        gmail_service=mock_gmail
    )

    assert len(results) == 1
    assert results[0].from_address == "security-alert@paypa1-security.com"
    assert service._history_state[user_email] == 1005


@pytest.mark.asyncio
async def test_mailbox_watch_manager_lifecycle():
    """
    Test MailboxWatchManager:
    - register_watch calls users().watch()
    - updates expiration and historyId
    - stop_watch calls users().stop()
    - renew_expiring_watches identifies watches near expiration
    """
    ingestion = GoogleIngestionService()
    manager = MailboxWatchManager(ingestion)

    user_email = "secops@example.com"
    topic = "projects/test-project/topics/gmail-events"

    # Mock Gmail service
    mock_gmail = MagicMock()
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    exp_ms = now_ms + (7 * 24 * 3600 * 1000)  # 7 days in future

    mock_watch = MagicMock()
    mock_watch.execute.return_value = {
        "historyId": "987654321",
        "expiration": str(exp_ms)
    }
    mock_gmail.users().watch.return_value = mock_watch

    mock_stop = MagicMock()
    mock_stop.execute.return_value = {}
    mock_gmail.users().stop.return_value = mock_stop

    # 1. Register Watch
    info = await manager.register_watch(
        user_email=user_email,
        topic_name=topic,
        label_ids=["INBOX", "UNREAD"],
        gmail_service=mock_gmail
    )

    assert info["user_email"] == user_email
    assert info["topic_name"] == topic
    assert info["history_id"] == "987654321"
    assert info["expiration_ms"] == exp_ms
    assert info["status"] == "active"
    assert user_email in manager.watched_mailboxes
    assert ingestion._history_state[user_email] == 987654321

    # Verify watch payload parameters
    mock_gmail.users().watch.assert_called_once_with(
        userId=user_email,
        body={
            "topicName": topic,
            "labelIds": ["INBOX", "UNREAD"],
            "labelFilterAction": "include"
        }
    )

    # 2. Test status inspection
    status_report = manager.get_status()
    assert status_report["total_watched_mailboxes"] == 1
    assert user_email in status_report["mailboxes"]

    # 3. Test renewal calculation: watch expiring in 10 hours should renew
    manager.watched_mailboxes[user_email]["expiration_ms"] = int((datetime.now(timezone.utc) + timedelta(hours=10)).timestamp() * 1000)
    renewed = await manager.renew_expiring_watches(renewal_window_hours=24, gmail_service=mock_gmail)
    assert len(renewed) == 1

    # 4. Stop Watch
    stopped = await manager.stop_watch(user_email=user_email, gmail_service=mock_gmail)
    assert stopped is True
    assert manager.watched_mailboxes[user_email]["status"] == "stopped"
    mock_gmail.users().stop.assert_called_once_with(userId=user_email)


@pytest.mark.asyncio
async def test_mailbox_watch_manager_demo_mode():
    """
    Test MailboxWatchManager graceful fallback to simulated watch
    when no GCP credentials or external APIs are available.
    """
    ingestion = GoogleIngestionService()
    manager = MailboxWatchManager(ingestion)

    demo_email = "employee-test@company.com"

    # Register watch with no credentials/service passed
    info = await manager.register_watch(user_email=demo_email)

    assert info["user_email"] == demo_email
    assert info["is_simulated"] is True
    assert "demo" in info["status"].lower()
    assert info["topic_name"] == "projects/tracex-demo/topics/gmail-inbox-watch"
    assert int(info["expiration_ms"]) > 0
    assert demo_email in manager.watched_mailboxes

    # Stop simulated watch
    stopped = await manager.stop_watch(user_email=demo_email)
    assert stopped is True
    assert manager.watched_mailboxes[demo_email]["status"] == "stopped"

