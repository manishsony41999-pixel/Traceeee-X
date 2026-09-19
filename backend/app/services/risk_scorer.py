"""
Risk Scoring Engine - Explainable risk score calculation based on evidence
"""
from typing import List
from app.schemas import RiskScoreBreakdown, RiskFactor


class RiskScorer:
    """Calculate explainable risk scores based on multiple threat indicators"""

    # Risk factor weights (out of 100 total points)
    WEIGHTS = {
        "spf_fail": 20,
        "dkim_fail": 18,
        "dmarc_fail": 20,
        "header_anomaly": 12,
        "phishing_keywords": 15,
        "urgency_language": 8,
        "financial_request": 18,
        "suspicious_url": 18,
        "url_shortener": 12,
        "ip_based_url": 15,
        "suspicious_tld": 10,
        "malicious_attachment": 25,
        "executable_attachment": 20,
        "macro_attachment": 18,
        "lookalike_domain": 22,
        "domain_mismatch": 15,
        "generic_greeting": 5,
        "malicious_ip": 20,
        "malicious_domain": 22,
        "known_threat": 30,
    }

    @classmethod
    def calculate_risk_score(
        cls,
        threat_indicators: List[str],
        threat_types: List[str],
        spf_status: str,
        dkim_status: str,
        dmarc_status: str,
        header_anomalies: List[str],
        malicious_ips: int = 0,
        malicious_domains: int = 0,
        malicious_urls: int = 0,
        malicious_attachments: int = 0
    ) -> RiskScoreBreakdown:
        """
        Calculate risk score with detailed breakdown.
        Score ranges from 0-100.
        """
        factors: List[RiskFactor] = []
        total_score = 0.0

        # Authentication failures
        if spf_status == "FAIL":
            points = cls.WEIGHTS["spf_fail"]
            total_score += points
            factors.append(RiskFactor(
                category="Authentication",
                points=points,
                description="SPF authentication failed",
                evidence_ref="spf_result"
            ))

        if dkim_status == "FAIL":
            points = cls.WEIGHTS["dkim_fail"]
            total_score += points
            factors.append(RiskFactor(
                category="Authentication",
                points=points,
                description="DKIM signature verification failed",
                evidence_ref="dkim_result"
            ))

        if dmarc_status == "FAIL":
            points = cls.WEIGHTS["dmarc_fail"]
            total_score += points
            factors.append(RiskFactor(
                category="Authentication",
                points=points,
                description="DMARC policy check failed",
                evidence_ref="dmarc_result"
            ))

        # Header anomalies
        anomaly_count = len(header_anomalies)
        if anomaly_count > 0:
            points = min(cls.WEIGHTS["header_anomaly"] * anomaly_count, 25)
            total_score += points
            factors.append(RiskFactor(
                category="Header Analysis",
                points=points,
                description=f"{anomaly_count} header anomal{'y' if anomaly_count == 1 else 'ies'} detected",
                evidence_ref="header_analysis"
            ))

        # Threat intelligence
        if malicious_ips > 0:
            points = cls.WEIGHTS["malicious_ip"]
            total_score += points
            factors.append(RiskFactor(
                category="Threat Intelligence",
                points=points,
                description=f"{malicious_ips} malicious IP address(es) identified",
                evidence_ref="ip_intelligence"
            ))

        if malicious_domains > 0:
            points = cls.WEIGHTS["malicious_domain"]
            total_score += points
            factors.append(RiskFactor(
                category="Threat Intelligence",
                points=points,
                description=f"{malicious_domains} malicious domain(s) identified",
                evidence_ref="domain_intelligence"
            ))

        if malicious_urls > 0:
            points = min(cls.WEIGHTS["suspicious_url"] * malicious_urls, 30)
            total_score += points
            factors.append(RiskFactor(
                category="URL Analysis",
                points=points,
                description=f"{malicious_urls} malicious URL(s) detected",
                evidence_ref="url_analysis"
            ))

        if malicious_attachments > 0:
            points = cls.WEIGHTS["malicious_attachment"]
            total_score += points
            factors.append(RiskFactor(
                category="Attachment Analysis",
                points=points,
                description=f"{malicious_attachments} malicious attachment(s) detected",
                evidence_ref="attachment_analysis"
            ))

        # Analyze threat indicators
        indicator_keywords = {
            "phishing": cls.WEIGHTS["phishing_keywords"],
            "urgency": cls.WEIGHTS["urgency_language"],
            "financial": cls.WEIGHTS["financial_request"],
            "url shortener": cls.WEIGHTS["url_shortener"],
            "ip-based url": cls.WEIGHTS["ip_based_url"],
            "suspicious tld": cls.WEIGHTS["suspicious_tld"],
            "executable": cls.WEIGHTS["executable_attachment"],
            "macro": cls.WEIGHTS["macro_attachment"],
            "lookalike": cls.WEIGHTS["lookalike_domain"],
            "domain mismatch": cls.WEIGHTS["domain_mismatch"],
            "generic greeting": cls.WEIGHTS["generic_greeting"],
        }

        for indicator in threat_indicators:
            indicator_lower = indicator.lower()
            for keyword, weight in indicator_keywords.items():
                if keyword in indicator_lower:
                    total_score += weight
                    factors.append(RiskFactor(
                        category="Content Analysis",
                        points=weight,
                        description=indicator,
                        evidence_ref="threat_detection"
                    ))
                    break

        # Cap at 100
        total_score = min(total_score, 100.0)

        # Determine severity
        if total_score >= 80:
            severity = "CRITICAL"
            explanation = "Multiple high-risk threat indicators detected. Immediate investigation required."
        elif total_score >= 60:
            severity = "HIGH"
            explanation = "Significant threat indicators present. Email likely malicious."
        elif total_score >= 40:
            severity = "MEDIUM"
            explanation = "Moderate risk indicators detected. Further analysis recommended."
        elif total_score >= 20:
            severity = "LOW"
            explanation = "Some suspicious characteristics, but may be legitimate."
        else:
            severity = "INFO"
            explanation = "No significant threat indicators detected."

        # Calculate confidence based on number of factors
        confidence = min(0.5 + (len(factors) * 0.1), 1.0)

        return RiskScoreBreakdown(
            score=round(total_score, 2),
            severity=severity,
            factors=factors,
            explanation=explanation,
            confidence=confidence
        )
