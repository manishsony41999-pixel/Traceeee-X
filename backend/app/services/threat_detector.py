"""
Threat Detection Engine - Rule-based detection for phishing, spoofing, and malicious indicators
"""
import re
from typing import List, Set, Optional, Dict, Any
from app.config import settings


class ThreatDetector:
    """Rule-based threat detection for common email attack patterns"""

    PHISHING_KEYWORDS = [
        "verify your account", "confirm your identity", "suspended account",
        "unusual activity", "click here immediately", "urgent action required",
        "your account will be closed", "verify payment", "confirm payment",
        "refund pending", "tax refund", "prize winner", "claim your prize",
        "reset your password", "update payment information", "billing problem",
        "suspend your account", "limited time offer", "act now", "dear customer",
        "dear user", "validate your account", "confirm ownership"
    ]

    URGENCY_KEYWORDS = [
        "urgent", "immediate", "action required", "respond now", "24 hours",
        "expires today", "last chance", "final notice", "time sensitive"
    ]

    FINANCIAL_KEYWORDS = [
        "wire transfer", "bank account", "credit card", "social security",
        "routing number", "account number", "pin code", "password", "ssn"
    ]

    SUSPICIOUS_URL_PATTERNS = [
        r'bit\.ly', r'tinyurl', r'goo\.gl', r't\.co',  # URL shorteners
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP-based URLs
        r'@',  # @ in URL (credential phishing)
    ]

    @classmethod
    def detect_threats(
        cls,
        subject: str,
        body_plain: str,
        body_html: str,
        from_address: str,
        reply_to: Optional[str],
        urls: List[str],
        attachments: List[dict],
        spf_status: str,
        dkim_status: str,
        dmarc_status: str,
        header_anomalies: List[str]
    ) -> dict:
        """
        Run comprehensive threat detection.
        Returns dict with detected threats and indicators.
        """
        indicators = []
        threat_types = set()

        full_text = f"{subject} {body_plain} {body_html}".lower()

        # 1. Authentication failures
        if spf_status == "FAIL":
            indicators.append("SPF authentication failed")
            threat_types.add("spoofing")

        if dkim_status == "FAIL":
            indicators.append("DKIM signature verification failed")
            threat_types.add("spoofing")

        if dmarc_status == "FAIL":
            indicators.append("DMARC policy failure")
            threat_types.add("spoofing")

        # 2. Header anomalies
        if header_anomalies:
            for anomaly in header_anomalies:
                indicators.append(f"Header anomaly: {anomaly}")
                if "domain" in anomaly.lower():
                    threat_types.add("spoofing")

        # 3. From/Reply-To mismatch
        if reply_to and reply_to != from_address:
            from_domain = cls._extract_domain(from_address)
            reply_domain = cls._extract_domain(reply_to)
            if from_domain != reply_domain:
                indicators.append(f"Reply-To address domain mismatch")
                threat_types.add("phishing")

        # 4. Phishing keyword detection
        phishing_matches = [kw for kw in cls.PHISHING_KEYWORDS if kw in full_text]
        if phishing_matches:
            indicators.append(f"Phishing keywords detected: {', '.join(phishing_matches[:3])}")
            threat_types.add("phishing")

        # 5. Urgency tactics
        urgency_matches = [kw for kw in cls.URGENCY_KEYWORDS if kw in full_text]
        if urgency_matches:
            indicators.append(f"Urgency language: {', '.join(urgency_matches[:2])}")
            threat_types.add("phishing")

        # 6. Financial information requests
        financial_matches = [kw for kw in cls.FINANCIAL_KEYWORDS if kw in full_text]
        if financial_matches:
            indicators.append(f"Requests financial data: {', '.join(financial_matches[:2])}")
            threat_types.add("credential_harvesting")

        # 7. URL analysis
        url_threats = cls._analyze_urls(urls)
        if url_threats:
            indicators.extend(url_threats)
            threat_types.add("phishing")

        # 8. Suspicious attachments
        attachment_threats = cls._analyze_attachments(attachments)
        if attachment_threats:
            indicators.extend(attachment_threats)
            threat_types.add("malware")

        # 9. Lookalike domains
        lookalike_check = cls._check_lookalike_domain(from_address, urls)
        if lookalike_check:
            indicators.extend(lookalike_check)
            threat_types.add("phishing")

        # 10. Generic greetings (often used in phishing)
        if re.search(r'\b(dear (customer|user|member|sir|madam))\b', full_text):
            indicators.append("Generic greeting (no personalization)")
            threat_types.add("phishing")

        return {
            "indicators": indicators,
            "threat_types": list(threat_types),
            "is_suspicious": len(indicators) > 0,
            "is_malicious": len(indicators) >= 3 or any(t in threat_types for t in ["malware", "credential_harvesting"])
        }

    @classmethod
    def _analyze_urls(cls, urls: List[str]) -> List[str]:
        """Detect suspicious URL characteristics"""
        threats = []

        for url in urls[:settings.MAX_URLS_PER_EMAIL]:
            # Check for URL shorteners
            if any(re.search(pattern, url, re.IGNORECASE) for pattern in cls.SUSPICIOUS_URL_PATTERNS):
                threats.append(f"Suspicious URL pattern: {url[:50]}...")

            # Check for IP-based URLs
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                threats.append(f"IP-based URL (not domain): {url[:50]}...")

            # Check for suspicious TLDs
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                if any(domain.endswith(tld) for tld in settings.SUSPICIOUS_TLDS):
                    threats.append(f"Suspicious TLD in URL: {domain}")
            except Exception:
                pass

            # Check for excessive subdomains
            try:
                parsed = urlparse(url)
                subdomain_count = parsed.netloc.count('.')
                if subdomain_count > 3:
                    threats.append(f"Excessive subdomains: {parsed.netloc}")
            except Exception:
                pass

        return threats

    @classmethod
    def _analyze_attachments(cls, attachments: List[dict]) -> List[str]:
        """Detect suspicious attachment characteristics"""
        threats = []

        for att in attachments[:settings.MAX_ATTACHMENTS_PER_EMAIL]:
            filename = att.get("filename", "")
            ext = att.get("file_extension", "")
            mime = att.get("mime_type", "")

            # Check for executable extensions
            if ext in settings.SUSPICIOUS_EXTENSIONS:
                threats.append(f"Executable/macro file attached: {filename}")

            # Check for double extensions
            if filename.count('.') > 1:
                threats.append(f"Double extension detected: {filename}")

            # Check for mismatch between extension and MIME type
            if ext == ".pdf" and "pdf" not in mime.lower():
                threats.append(f"Extension/MIME mismatch: {filename}")

            # Check for extremely long filenames (obfuscation technique)
            if len(filename) > 100:
                threats.append(f"Unusually long filename: {filename[:30]}...")

        return threats

    @classmethod
    def _check_lookalike_domain(cls, from_address: str, urls: List[str]) -> List[str]:
        """
        Check for lookalike/typosquatting domains.
        This is a simple implementation - production would use edit distance algorithms.
        """
        threats = []

        # Common lookalike characters
        lookalikes = {
            'o': '0', '0': 'o',
            'l': '1', '1': 'l', 'i': '1',
            'm': 'rn', 'rn': 'm'
        }

        # Common legitimate domains to check against
        legitimate_domains = [
            "paypal.com", "amazon.com", "microsoft.com", "apple.com",
            "google.com", "facebook.com", "netflix.com", "linkedin.com"
        ]

        from_domain = cls._extract_domain(from_address)
        if from_domain:
            for legit in legitimate_domains:
                # Simple check: if domains are very similar but not exact
                if legit not in from_domain and cls._similarity_score(from_domain, legit) > 0.7:
                    threats.append(f"Possible lookalike domain: {from_domain} resembles {legit}")

        # Check URLs for lookalikes
        for url in urls[:20]:
            try:
                parsed = urlparse(url)
                url_domain = parsed.netloc.lower()
                for legit in legitimate_domains:
                    if legit not in url_domain and cls._similarity_score(url_domain, legit) > 0.7:
                        threats.append(f"URL contains lookalike domain: {url_domain} resembles {legit}")
                        break
            except Exception:
                pass

        return threats

    @staticmethod
    def _extract_domain(email_address: str) -> Optional[str]:
        """Extract domain from email address"""
        if not email_address or "@" not in email_address:
            return None
        return email_address.split("@")[-1].lower().strip()

    @staticmethod
    def _similarity_score(s1: str, s2: str) -> float:
        """Simple character-based similarity score (0.0 to 1.0)"""
        if not s1 or not s2:
            return 0.0

        # Count matching characters
        matches = sum(1 for a, b in zip(s1, s2) if a == b)
        max_len = max(len(s1), len(s2))

        return matches / max_len if max_len > 0 else 0.0


from typing import Optional
