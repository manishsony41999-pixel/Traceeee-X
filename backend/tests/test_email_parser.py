"""
Unit tests for Email Parser Service
"""
import pytest
from app.services.email_parser import EmailParserService


def test_parse_simple_email():
    """Test parsing a basic RFC 822 email"""
    raw_email = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Wed, 18 Sep 2024 10:00:00 +0000

This is a test message.
"""
    parsed = EmailParserService.parse_raw_email(raw_email)

    assert parsed.from_address == "sender@example.com"
    assert "recipient@example.com" in parsed.to_addresses
    assert parsed.subject == "Test Email"
    assert "test message" in parsed.body_plain.lower()


def test_parse_multipart_email():
    """Test parsing multipart MIME email with HTML and plain text"""
    raw_email = """From: test@example.com
To: user@example.com
Subject: Multipart Test
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain

Plain text body
--boundary123
Content-Type: text/html

<html><body>HTML body</body></html>
--boundary123--
"""
    parsed = EmailParserService.parse_raw_email(raw_email)

    assert "Plain text body" in parsed.body_plain
    assert "HTML body" in parsed.body_html


def test_extract_urls_from_email():
    """Test URL extraction from email body"""
    raw_email = """From: sender@example.com
To: recipient@example.com
Subject: URLs Test

Check out https://example.com and http://test.org/path?query=1
"""
    parsed = EmailParserService.parse_raw_email(raw_email)

    assert len(parsed.urls) >= 2
    assert any("example.com" in url for url in parsed.urls)
    assert any("test.org" in url for url in parsed.urls)


def test_parse_headers():
    """Test header extraction"""
    raw_email = """From: test@example.com
To: user@example.com
X-Custom-Header: CustomValue
Subject: Header Test

Body
"""
    parsed = EmailParserService.parse_raw_email(raw_email)

    assert "x-custom-header" in parsed.headers_dict
    assert parsed.headers_dict["x-custom-header"][0] == "CustomValue"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
