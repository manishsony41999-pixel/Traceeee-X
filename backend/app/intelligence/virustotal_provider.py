"""
VirusTotal v3 Threat Intelligence Provider
Queries VirusTotal API for file hashes, domains, URLs, and IP addresses.
"""
import httpx
import base64
from typing import Optional, Dict, Any
from app.intelligence.base import IntelligenceProvider, ProviderUnavailableError, ProviderRateLimitError
from app.schemas import IPIntelligenceData, DomainIntelligenceData


class VirusTotalProvider(IntelligenceProvider):
    """Integration with VirusTotal v3 REST API"""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key)
        self.provider_name = "VirusTotal"

    async def get_ip_intelligence(self, ip_address: str) -> Optional[IPIntelligenceData]:
        """Fetch IP reputation from VirusTotal"""
        if not self.api_key:
            raise ProviderUnavailableError("VirusTotal API key is not configured")

        headers = {"x-apikey": self.api_key}
        url = f"{self.BASE_URL}/ip_addresses/{ip_address}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    raise ProviderRateLimitError("VirusTotal rate limit exceeded")
                if resp.status_code != 200:
                    return None

                data = resp.json().get("data", {})
                attributes = data.get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})

                malicious_count = last_analysis_stats.get("malicious", 0)
                suspicious_count = last_analysis_stats.get("suspicious", 0)
                harmless_count = last_analysis_stats.get("harmless", 0)

                total_engines = sum(last_analysis_stats.values()) or 1
                reputation_score = round(max(0, 100 - (malicious_count * 15 + suspicious_count * 5)), 2)

                return IPIntelligenceData(
                    ip_address=ip_address,
                    country=attributes.get("country"),
                    country_code=attributes.get("country"),
                    region=None,
                    city=None,
                    isp=attributes.get("as_owner"),
                    asn=str(attributes.get("asn", "")),
                    organization=attributes.get("as_owner"),
                    is_hosting=None,
                    reputation_score=reputation_score,
                    is_malicious=malicious_count > 0,
                    abuse_confidence_score=float(malicious_count * 10),
                    total_reports=malicious_count,
                    provider="VirusTotal",
                    context_note="Intelligence provided via VirusTotal API.",
                    is_demo=False
                )
        except httpx.RequestError:
            return None

    async def get_domain_intelligence(self, domain: str) -> Optional[DomainIntelligenceData]:
        """Fetch domain reputation from VirusTotal"""
        if not self.api_key:
            raise ProviderUnavailableError("VirusTotal API key is not configured")

        headers = {"x-apikey": self.api_key}
        url = f"{self.BASE_URL}/domains/{domain}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    raise ProviderRateLimitError("VirusTotal rate limit exceeded")
                if resp.status_code != 200:
                    return None

                data = resp.json().get("data", {})
                attributes = data.get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})

                malicious_count = last_analysis_stats.get("malicious", 0)
                suspicious_count = last_analysis_stats.get("suspicious", 0)
                reputation_score = round(max(0, 100 - (malicious_count * 15 + suspicious_count * 5)), 2)

                threat_types = []
                if malicious_count > 0:
                    threat_types.append("malicious")
                if suspicious_count > 0:
                    threat_types.append("suspicious")

                return DomainIntelligenceData(
                    domain=domain,
                    registrar=attributes.get("registrar"),
                    is_malicious=malicious_count > 0,
                    is_suspicious=suspicious_count > 0,
                    reputation_score=reputation_score,
                    threat_types=threat_types,
                    provider="VirusTotal",
                    is_demo=False
                )
        except httpx.RequestError:
            return None

    async def get_url_reputation(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch URL scan results from VirusTotal"""
        if not self.api_key:
            raise ProviderUnavailableError("VirusTotal API key is not configured")

        # VirusTotal requires base64 encoded URL identifier (without padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.api_key}
        api_url = f"{self.BASE_URL}/urls/{url_id}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(api_url, headers=headers)
                if resp.status_code == 429:
                    raise ProviderRateLimitError("VirusTotal rate limit exceeded")
                if resp.status_code != 200:
                    return None

                data = resp.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                return {
                    "url": url,
                    "is_malicious": malicious > 0,
                    "is_suspicious": suspicious > 0,
                    "malicious_votes": malicious,
                    "suspicious_votes": suspicious,
                    "harmless_votes": stats.get("harmless", 0),
                    "reputation_score": round(max(0, 100 - (malicious * 20 + suspicious * 10)), 2),
                    "provider": "VirusTotal",
                    "is_demo": False
                }
        except httpx.RequestError:
            return None

    async def get_file_reputation(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch file hash reputation from VirusTotal"""
        if not self.api_key:
            raise ProviderUnavailableError("VirusTotal API key is not configured")

        headers = {"x-apikey": self.api_key}
        url = f"{self.BASE_URL}/files/{file_hash}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    raise ProviderRateLimitError("VirusTotal rate limit exceeded")
                if resp.status_code != 200:
                    return None

                data = resp.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                return {
                    "hash": file_hash,
                    "is_malicious": malicious > 0,
                    "is_suspicious": suspicious > 0,
                    "detection_count": malicious,
                    "total_engines": sum(stats.values()),
                    "meaningful_name": attributes.get("meaningful_name"),
                    "provider": "VirusTotal",
                    "is_demo": False
                }
        except httpx.RequestError:
            return None
