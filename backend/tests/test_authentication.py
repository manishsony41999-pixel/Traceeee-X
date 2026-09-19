"""
Unit tests for Authentication Analyzer
"""
import pytest
from app.services.authentication_analyzer import AuthenticationAnalyzer
from app.schemas import AuthStatusEnum


def test_spf_pass():
    """Test SPF PASS detection"""
    headers = {
        "received-spf": ["pass (google.com: domain of sender@example.com designates 1.2.3.4 as permitted sender)"]
    }

    result = AuthenticationAnalyzer._analyze_spf(headers, "sender@example.com")
    assert result.status == AuthStatusEnum.PASS


def test_spf_fail():
    """Test SPF FAIL detection"""
    headers = {
        "received-spf": ["fail (google.com: domain of sender@example.com does not designate 5.6.7.8 as permitted sender)"]
    }

    result = AuthenticationAnalyzer._analyze_spf(headers, "sender@example.com")
    assert result.status == AuthStatusEnum.FAIL


def test_dkim_pass():
    """Test DKIM PASS detection"""
    headers = {
        "authentication-results": ["mx.example.com; dkim=pass header.i=@example.com"]
    }

    result = AuthenticationAnalyzer._analyze_dkim(headers)
    assert result.status == AuthStatusEnum.PASS


def test_dkim_fail():
    """Test DKIM FAIL detection"""
    headers = {
        "authentication-results": ["mx.example.com; dkim=fail (bad signature) header.i=@example.com"]
    }

    result = AuthenticationAnalyzer._analyze_dkim(headers)
    assert result.status == AuthStatusEnum.FAIL


def test_dmarc_pass():
    """Test DMARC PASS detection"""
    headers = {
        "authentication-results": ["mx.example.com; dmarc=pass header.from=example.com"]
    }

    result = AuthenticationAnalyzer._analyze_dmarc(
        headers, "test@example.com", AuthStatusEnum.PASS, AuthStatusEnum.PASS
    )
    assert result.status == AuthStatusEnum.PASS


def test_dmarc_fail():
    """Test DMARC FAIL detection"""
    headers = {
        "authentication-results": ["mx.example.com; dmarc=fail header.from=example.com"]
    }

    result = AuthenticationAnalyzer._analyze_dmarc(
        headers, "test@example.com", AuthStatusEnum.FAIL, AuthStatusEnum.FAIL
    )
    assert result.status == AuthStatusEnum.FAIL


def test_full_authentication_analysis():
    """Test complete authentication analysis"""
    headers = {
        "received-spf": ["pass"],
        "authentication-results": [
            "mx.example.com; dkim=pass; dmarc=pass"
        ]
    }

    analysis = AuthenticationAnalyzer.analyze(headers, "sender@example.com")

    assert analysis.spf.status == AuthStatusEnum.PASS
    assert analysis.dkim.status == AuthStatusEnum.PASS
    assert analysis.dmarc.status == AuthStatusEnum.PASS
    assert "passed" in analysis.summary.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
