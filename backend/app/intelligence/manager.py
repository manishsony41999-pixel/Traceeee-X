"""
Threat Intelligence Manager
Coordinates multiple threat intelligence providers with caching, aggregation, and fallback.
"""
from typing import Optional, Dict, Any, List
from app.config import settings
from app.intelligence.base import IntelligenceProvider
from app.intelligence.virustotal_provider import VirusTotalProvider
from app.intelligence.abuseipdb_provider import AbuseIPDBProvider
from app.intelligence.ipinfo_provider import IPGeolocationProvider
from app.intelligence.demo_provider import DemoIntelligenceProvider
from app.schemas import IPIntelligenceData, DomainIntelligenceData


class ThreatIntelligenceManager:
    """
    Central orchestration point for IP, Domain, URL, and Attachment Intelligence.
    Ensures graceful degradation: if an external API key is missing or fails,
    it falls back to local/demo intelligence while clearly marking the source.
    """

    def __init__(self):
        self.demo_provider = DemoIntelligenceProvider()
        self.ip_geo_provider = IPGeolocationProvider(settings.IP_GEOLOCATION_API_KEY)
        self.abuseipdb_provider = AbuseIPDBProvider(settings.ABUSEIPDB_API_KEY)
        self.vt_provider = VirusTotalProvider(settings.VIRUSTOTAL_API_KEY)

        # In-memory cache for repeated lookups during analysis sessions
        self._ip_cache: Dict[str, IPIntelligenceData] = {}
        self._domain_cache: Dict[str, DomainIntelligenceData] = {}
        self._url_cache: Dict[str, Dict[str, Any]] = {}

    async def get_ip_intelligence(self, ip_address: str) -> IPIntelligenceData:
        """Fetch IP intelligence using configured providers with fallback"""
        if not ip_address:
            return await self.demo_provider.get_ip_intelligence("0.0.0.0")

        if ip_address in self._ip_cache:
            return self._ip_cache[ip_address]

        # 1. Try real IP Geolocation provider
        geo_result = None
        try:
            geo_result = await self.ip_geo_provider.get_ip_intelligence(ip_address)
        except Exception:
            pass

        # 2. Try AbuseIPDB if configured
        abuse_result = None
        if settings.ABUSEIPDB_API_KEY:
            try:
                abuse_result = await self.abuseipdb_provider.get_ip_intelligence(ip_address)
            except Exception:
                pass

        # 3. Try VirusTotal if configured
        vt_result = None
        if settings.VIRUSTOTAL_API_KEY:
            try:
                vt_result = await self.vt_provider.get_ip_intelligence(ip_address)
            except Exception:
                pass

        # Merge results if real providers returned data
        if geo_result or abuse_result or vt_result:
            merged = geo_result or abuse_result or vt_result
            if abuse_result and geo_result:
                merged.reputation_score = min(geo_result.reputation_score or 100, abuse_result.reputation_score or 100)
                merged.abuse_confidence_score = abuse_result.abuse_confidence_score
                merged.total_reports = abuse_result.total_reports
                merged.is_malicious = abuse_result.is_malicious or geo_result.is_malicious
                merged.provider = f"{geo_result.provider} + {abuse_result.provider}"
            self._ip_cache[ip_address] = merged
            return merged

        # Fallback to demo provider
        demo_res = await self.demo_provider.get_ip_intelligence(ip_address)
        self._ip_cache[ip_address] = demo_res
        return demo_res

    async def get_domain_intelligence(self, domain: str) -> DomainIntelligenceData:
        """Fetch domain intelligence with fallback"""
        if not domain:
            return await self.demo_provider.get_domain_intelligence("unknown.local")

        norm_domain = domain.lower().strip()
        if norm_domain in self._domain_cache:
            return self._domain_cache[norm_domain]

        # Try VirusTotal if configured
        if settings.VIRUSTOTAL_API_KEY:
            try:
                vt_res = await self.vt_provider.get_domain_intelligence(norm_domain)
                if vt_res:
                    self._domain_cache[norm_domain] = vt_res
                    return vt_res
            except Exception:
                pass

        # Fallback to demo provider
        demo_res = await self.demo_provider.get_domain_intelligence(norm_domain)
        self._domain_cache[norm_domain] = demo_res
        return demo_res

    async def get_url_reputation(self, url: str) -> Dict[str, Any]:
        """Fetch URL reputation with fallback"""
        if url in self._url_cache:
            return self._url_cache[url]

        if settings.VIRUSTOTAL_API_KEY:
            try:
                vt_res = await self.vt_provider.get_url_reputation(url)
                if vt_res:
                    self._url_cache[url] = vt_res
                    return vt_res
            except Exception:
                pass

        demo_res = await self.demo_provider.get_url_reputation(url)
        self._url_cache[url] = demo_res
        return demo_res

    async def get_file_reputation(self, sha256_hash: str) -> Dict[str, Any]:
        """Fetch file hash reputation with fallback"""
        if settings.VIRUSTOTAL_API_KEY and sha256_hash:
            try:
                vt_res = await self.vt_provider.get_file_reputation(sha256_hash)
                if vt_res:
                    return vt_res
            except Exception:
                pass

        return await self.demo_provider.get_file_reputation(sha256_hash)


# Global singleton instance
threat_intelligence_manager = ThreatIntelligenceManager()
