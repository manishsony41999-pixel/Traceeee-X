"""
AbuseIPDB Threat Intelligence Provider
Queries AbuseIPDB API for IP address reputation, abuse confidence score, and attack categories.
"""
import httpx
from typing import Optional, Dict, Any
from app.intelligence.base import IntelligenceProvider, ProviderUnavailableError, ProviderRateLimitError
from app.schemas import IPIntelligenceData, DomainIntelligenceData


class AbuseIPDBProvider(IntelligenceProvider):
    """Integration with AbuseIPDB v2 REST API"""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key)
        self.provider_name = "AbuseIPDB"

    async def get_ip_intelligence(self, ip_address: str) -> Optional[IPIntelligenceData]:
        """Fetch IP reputation from AbuseIPDB"""
        if not self.api_key:
            raise ProviderUnavailableError("AbuseIPDB API key is not configured")

        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": "90",
            "verbose": True
        }
        url = f"{self.BASE_URL}/check"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers, params=params)
                if resp.status_code == 429:
                    raise ProviderRateLimitError("AbuseIPDB rate limit exceeded")
                if resp.status_code != 200:
                    return None

                data = resp.json().get("data", {})
                abuse_score = float(data.get("abuseConfidenceScore", 0))
                total_reports = int(data.get("totalReports", 0))
                is_malicious = abuse_score >= 25 or total_reports > 5

                # Compute normalized reputation score (100 is best, 0 is worst)
                reputation_score = round(max(0.0, 100.0 - abuse_score), 2)

                return IPIntelligenceData(
                    ip_address=ip_address,
                    country=data.get("countryName"),
                    country_code=data.get("countryCode"),
                    isp=data.get("isp"),
                    asn=None,
                    organization=data.get("usageType"),
                    is_hosting="Data Center" in str(data.get("usageType", "")),
                    is_tor=data.get("isTor", False),
                    reputation_score=reputation_score,
                    is_malicious=is_malicious,
                    abuse_confidence_score=abuse_score,
                    total_reports=total_reports,
                    provider="AbuseIPDB",
                    context_note="Contextual reputation score based on public abuse reports.",
                    is_demo=False
                )
        except httpx.RequestError:
            return None

    async def get_domain_intelligence(self, domain: str) -> Optional[DomainIntelligenceData]:
        return None

    async def get_url_reputation(self, url: str) -> Optional[Dict[str, Any]]:
        return None

    async def get_file_reputation(self, file_hash: str) -> Optional[Dict[str, Any]]:
        return None
