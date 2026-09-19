"""
Unit tests for Google Cloud Pub/Sub Webhook Endpoints
"""
import base64
import json
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.api.v1.webhooks import decode_pubsub_base64, extract_pubsub_credentials
from app.config import settings

client = TestClient(app)


def test_decode_pubsub_base64_standard():
    """Test decoding standard base64 Pub/Sub payload"""
    inner_payload = {"emailAddress": "user@example.com", "historyId": "54321"}
    b64_str = base64.b64encode(json.dumps(inner_payload).encode("utf-8")).decode("utf-8")

    decoded = decode_pubsub_base64(b64_str)
    assert decoded["emailAddress"] == "user@example.com"
    assert decoded["historyId"] == "54321"


def test_decode_pubsub_base64_urlsafe_and_unpadded():
    """Test decoding URL-safe unpadded base64 Pub/Sub payload"""
    inner_payload = {"emailAddress": "analyst@tracex.local", "historyId": "999888"}
    b64_str = base64.urlsafe_b64encode(json.dumps(inner_payload).encode("utf-8")).decode("utf-8").rstrip("=")

    decoded = decode_pubsub_base64(b64_str)
    assert decoded["emailAddress"] == "analyst@tracex.local"
    assert decoded["historyId"] == "999888"


def test_extract_pubsub_credentials():
    """Test extracting email and historyId from standard Pub/Sub envelope"""
    inner = {"emailAddress": "victim@domain.com", "historyId": "777"}
    envelope = {
        "message": {
            "data": base64.b64encode(json.dumps(inner).encode("utf-8")).decode("utf-8"),
            "messageId": "12345",
            "publishTime": "2026-09-19T07:00:00Z"
        },
        "subscription": "projects/p/subscriptions/s"
    }

    email, history_id = extract_pubsub_credentials(envelope)
    assert email == "victim@domain.com"
    assert history_id == "777"


def test_extract_pubsub_credentials_direct_json():
    """Test direct JSON payload fallback"""
    payload = {"emailAddress": "direct@domain.com", "historyId": 12345}
    email, history_id = extract_pubsub_credentials(payload)
    assert email == "direct@domain.com"
    assert history_id == "12345"


def test_webhook_google_pubsub_post_accepted():
    """
    Test POST /api/v1/webhook/google-pubsub successfully accepts and returns 200 OK
    """
    inner = {"emailAddress": "target@tracex.test", "historyId": "888123"}
    data_b64 = base64.b64encode(json.dumps(inner).encode("utf-8")).decode("utf-8")

    payload = {
        "message": {
            "data": data_b64,
            "messageId": "msg-id-100",
            "publishTime": "2026-09-19T07:00:00Z"
        },
        "subscription": "projects/tracex/subscriptions/sub"
    }

    with patch("app.services.google_ingestion.google_ingestion_service.process_history_notification", new_callable=AsyncMock) as mock_process:
        response = client.post("/api/v1/webhook/google-pubsub", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"
        assert data["user_email"] == "target@tracex.test"
        assert data["history_id"] == "888123"


def test_webhook_google_pubsub_token_verification():
    """Test token verification on webhook endpoint"""
    inner = {"emailAddress": "target@tracex.test", "historyId": "888123"}
    data_b64 = base64.b64encode(json.dumps(inner).encode("utf-8")).decode("utf-8")
    payload = {"message": {"data": data_b64}}

    # Set verification token in settings
    with patch.object(settings, "GOOGLE_PUBSUB_VERIFICATION_TOKEN", "SECRET_KEY_123"):
        # Without token -> 401
        res_no_tok = client.post("/api/v1/webhook/google-pubsub", json=payload)
        assert res_no_tok.status_code == 401

        # With wrong token -> 401
        res_bad_tok = client.post("/api/v1/webhook/google-pubsub?token=WRONG", json=payload)
        assert res_bad_tok.status_code == 401

        # With valid token -> 200
        res_ok = client.post("/api/v1/webhook/google-pubsub?token=SECRET_KEY_123", json=payload)
        assert res_ok.status_code == 200


def test_webhook_google_pubsub_status():
    """Test GET /api/v1/webhook/google-pubsub/status"""
    response = client.get("/api/v1/webhook/google-pubsub/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "watch_manager" in data


def test_simulate_ingestion_endpoint():
    """
    Test POST /api/v1/webhook/google-pubsub/simulate endpoint
    Ingests a raw email and verifies threat analysis response
    """
    raw_email = """From: attacker@suspicious-login.com
To: user@company.com
Subject: Password Reset Required Immediately
Date: Sat, 19 Sep 2026 07:00:00 +0000

Please verify your credentials at: http://fake-login.biz/reset
"""
    payload = {
        "user_email": "user@company.com",
        "raw_email": raw_email,
        "broadcast_websocket": True
    }

    response = client.post("/api/v1/webhook/google-pubsub/simulate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ingested"
    assert "risk_score" in data
    assert "email_id" in data
    assert data["analysis"]["from_address"] == "attacker@suspicious-login.com"
