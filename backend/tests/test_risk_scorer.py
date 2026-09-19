"""
Unit tests for Risk Scoring Engine
"""
import pytest
from app.services.risk_scorer import RiskScorer


def test_clean_email_low_risk():
    """Test risk scoring for clean email with no threats"""
    risk = RiskScorer.calculate_risk_score(
        threat_indicators=[],
        threat_types=[],
        spf_status="PASS",
        dkim_status="PASS",
        dmarc_status="PASS",
        header_anomalies=[],
        malicious_ips=0,
        malicious_domains=0,
        malicious_urls=0,
        malicious_attachments=0
    )

    assert risk.score < 20.0
    assert risk.severity in ["INFO", "LOW"]
    assert len(risk.factors) == 0


def test_authentication_failure_high_risk():
    """Test risk scoring for email with authentication failures"""
    risk = RiskScorer.calculate_risk_score(
        threat_indicators=["Phishing keywords detected"],
        threat_types=["phishing"],
        spf_status="FAIL",
        dkim_status="FAIL",
        dmarc_status="FAIL",
        header_anomalies=["Reply-To domain mismatch"],
        malicious_ips=0,
        malicious_domains=0,
        malicious_urls=0,
        malicious_attachments=0
    )

    assert risk.score >= 60.0
    assert risk.severity in ["HIGH", "CRITICAL"]
    assert any("SPF" in f.description for f in risk.factors)
    assert any("DKIM" in f.description for f in risk.factors)
    assert any("DMARC" in f.description for f in risk.factors)


def test_malicious_intelligence_critical_risk():
    """Test risk scoring with malicious threat intelligence"""
    risk = RiskScorer.calculate_risk_score(
        threat_indicators=["Suspicious URL pattern"],
        threat_types=["phishing", "malware"],
        spf_status="FAIL",
        dkim_status="FAIL",
        dmarc_status="FAIL",
        header_anomalies=[],
        malicious_ips=1,
        malicious_domains=1,
        malicious_urls=2,
        malicious_attachments=1
    )

    assert risk.score >= 80.0
    assert risk.severity == "CRITICAL"


def test_risk_factors_explainability():
    """Test that risk breakdown includes explainable factors"""
    risk = RiskScorer.calculate_risk_score(
        threat_indicators=["Urgency language", "Financial data request"],
        threat_types=["phishing"],
        spf_status="FAIL",
        dkim_status="PASS",
        dmarc_status="FAIL",
        header_anomalies=["Domain mismatch"],
        malicious_ips=0,
        malicious_domains=0,
        malicious_urls=0,
        malicious_attachments=0
    )

    assert len(risk.factors) > 0
    for factor in risk.factors:
        assert factor.category
        assert factor.points > 0
        assert factor.description


def test_score_capped_at_100():
    """Test that risk score never exceeds 100"""
    risk = RiskScorer.calculate_risk_score(
        threat_indicators=["indicator1", "indicator2", "indicator3"] * 10,
        threat_types=["phishing", "malware", "spoofing"],
        spf_status="FAIL",
        dkim_status="FAIL",
        dmarc_status="FAIL",
        header_anomalies=["anomaly1", "anomaly2", "anomaly3"],
        malicious_ips=5,
        malicious_domains=5,
        malicious_urls=10,
        malicious_attachments=5
    )

    assert risk.score <= 100.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
