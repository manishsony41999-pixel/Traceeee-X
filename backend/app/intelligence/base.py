"""
Base provider interface for threat intelligence services
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from app.schemas import IPIntelligenceData, DomainIntelligenceData


class IntelligenceProvider(ABC):
    """Abstract base class for all threat intelligence providers"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.provider_name = self.__class__.__name__

    @abstractmethod
    async def get_ip_intelligence(self, ip_address: str) -> Optional[IPIntelligenceData]:
        """Fetch IP address intelligence and geolocation"""
        pass

    @abstractmethod
    async def get_domain_intelligence(self, domain: str) -> Optional[DomainIntelligenceData]:
        """Fetch domain reputation and WHOIS data"""
        pass

    @abstractmethod
    async def get_url_reputation(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch URL reputation and scan results"""
        pass

    @abstractmethod
    async def get_file_reputation(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch file reputation by hash"""
        pass

    async def is_available(self) -> bool:
        """Check if provider is configured and available"""
        return self.api_key is not None


class ProviderUnavailableError(Exception):
    """Raised when a provider is not available or configured"""
    pass


class ProviderTimeoutError(Exception):
    """Raised when a provider request times out"""
    pass


class ProviderRateLimitError(Exception):
    """Raised when rate limit is exceeded"""
    pass
