"""
Unit and Integration Tests for AI SOC Analyst Copilot Chat API
"""
import pytest
from httpx import AsyncClient
from app.main import app
from app.services.ai_analyzer import ai_analyzer


@pytest.mark.asyncio
async def test_chat_status_endpoint():
    """Test GET /api/v1/chat/status returns operational status"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/v1/chat/status")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"
        assert "TRACE-X AI SOC Copilot" in data["service"]
        assert data["offline_heuristic_fallback_ready"] is True
        assert len(data["supported_capabilities"]) > 0


@pytest.mark.asyncio
async def test_chat_query_empty_messages_rejected():
    """Test POST /api/v1/chat/query rejects empty messages array with 400"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/api/v1/chat/query", json={"messages": []})
        assert response.status_code == 400
        assert "cannot be empty" in response.json()["detail"]


@pytest.mark.asyncio
async def test_chat_query_auth_failure_with_threat_context():
    """
    Test POST /api/v1/chat/query:
    Explaining SPF/DKIM/DMARC failures with active incident threat context.
    """
    threat_context = {
        "email_id": "test-incident-991",
        "subject": "URGENT: Payroll Account Verification",
        "from_address": "support@paypa1-security.com",
        "to_address": "cfo@company.com",
        "risk_score": 92.5,
        "severity": "CRITICAL",
        "threat_type": "phishing",
        "is_malicious": True,
        "spf_result": "FAIL",
        "dkim_result": "FAIL",
        "dmarc_result": "FAIL",
        "header_anomalies": ["Reply-To address differs from From domain", "High transit hop latency (42 mins)"]
    }

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/chat/query",
            json={
                "messages": [
                    {"role": "user", "content": "Explain why this email failed SPF, DKIM, and DMARC authentication."}
                ],
                "threat_context": threat_context
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "assistant"
        assert data["threat_context_applied"] is True
        assert "SPF" in data["response"]
        assert "DKIM" in data["response"]
        assert "DMARC" in data["response"]
        assert "support@paypa1-security.com" in data["response"]
        assert len(data["suggested_actions"]) > 0


@pytest.mark.asyncio
async def test_chat_query_containment_playbook():
    """Test POST /api/v1/chat/query returns a structured containment playbook"""
    threat_context = {
        "subject": "CEO Wire Request",
        "from_address": "ceo-office@spoofed-domain.com",
        "threat_type": "bec",
        "risk_score": 88
    }

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/chat/query",
            json={
                "messages": [
                    {"role": "user", "content": "What is the containment playbook for this incident?"}
                ],
                "threat_context": threat_context
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "Playbook" in data["response"] or "Containment" in data["response"]
        assert "Perimeter" in data["response"] or "Gateway" in data["response"]
        assert "Mailbox" in data["response"] or "Purge" in data["response"]
        assert len(data["suggested_actions"]) > 0


@pytest.mark.asyncio
async def test_chat_query_threat_hunting_kql():
    """Test POST /api/v1/chat/query generates KQL and Splunk hunting queries"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/chat/query",
            json={
                "messages": [
                    {"role": "user", "content": "Generate a KQL query to hunt for this threat across Microsoft Sentinel."}
                ],
                "threat_context": {
                    "from_address": "malicious-phish@attacker.org",
                    "subject": "Invoice Statement Attached"
                }
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "EmailEvents" in data["response"] or "kql" in data["response"].lower()
        assert "malicious-phish@attacker.org" in data["response"]


@pytest.mark.asyncio
async def test_chat_query_header_anomaly_investigation():
    """Test POST /api/v1/chat/query decodes header anomalies"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/chat/query",
            json={
                "messages": [
                    {"role": "user", "content": "How do I decode the Received headers and check for anomalies?"}
                ],
                "threat_context": {
                    "header_anomalies": ["Suspect relay: 192.168.1.1", "Reply-To mismatch"]
                }
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "Received" in data["response"]
        assert "Reply-To" in data["response"]
