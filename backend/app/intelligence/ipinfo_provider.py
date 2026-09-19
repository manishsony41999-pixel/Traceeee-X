"""
IP Geolocation & Network Provider (IP-API / ipinfo.io)
Extracts geographic location, ASN, ISP, and hosting flags for IP addresses.
"""
import httpx
from typing import Optional, Dict, Any
from app.intelligence.base import IntelligenceProvider
from app.schemas import IPIntelligenceData, DomainIntelligenceData


class IPGeolocationProvider(IntelligenceProvider):
    """
    Queries standard IP Geolocation services (IP-API free tier / ipinfo)
    Provides country, city, coordinates, ISP, and ASN metadata.
    """

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key)
        self.provider_name = "IPGeolocation"

    async def get_ip_intelligence(self, ip_address: str) -> Optional[IPIntelligenceData]:
        """Fetch geolocation data from IP-API (free endpoint for non-commercial/testing)"""
        # Skip private / loopback IP ranges
        if self._is_private_ip(ip_address):
            return IPIntelligenceData(
                ip_address=ip_address,
                country="Internal / Private Network",
                isp="Local Network / Private RFC 1918",
                reputation_score=100.0,
                is_malicious=False,
                provider="LocalFilter",
                context_note="Private IP space cannot be geographically resolved over the public internet.",
                is_demo=False
            )

        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,hosting,proxy"

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        is_proxy = data.get("proxy", False)
                        is_hosting = data.get("hosting", False)

                        # Suspicious if hosting/datacenter or proxy acting as direct mail sender
                        is_suspicious = is_proxy

                        return IPIntelligenceData(
                            ip_address=ip_address,
                            country=data.get("country"),
                            country_code=data.get("countryCode"),
                            region=data.get("regionName"),
                            city=data.get("city"),
                            latitude=data.get("lat"),
                            longitude=data.get("lon"),
                            isp=data.get("isp"),
                            asn=data.get("as"),
                            organization=data.get("org"),
                            is_hosting=is_hosting,
                            is_proxy=is_proxy,
                            reputation_score=60.0 if is_proxy else 90.0,
                            is_malicious=False,
                            provider="IP-API",
                            context_note="Geolocation is contextual intelligence and does not establish physical attribution.",
                            is_demo=False
                        )
        except Exception:
            pass

        return None

    async def get_domain_intelligence(self, domain: str) -> Optional[DomainIntelligenceData]:
        return None

    async def get_url_reputation(self, url: str) -> Optional[Dict[str, Any]]:
        return None

    async def get_file_reputation(self, file_hash: str) -> Optional[Dict[str, Any]]:
        return None

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is in private/reserved RFC 1918 ranges"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            o1, o2 = int(parts[0]), int(parts[1])
            if o1 == 10:
                return True
            if o1 == 172 and 16 <= o2 <= 31:
                return True
            if o1 == 192 and o2 == 168:
                return True
            if o1 == 127:
                return True
        except ValueError:
            return False
        return False
