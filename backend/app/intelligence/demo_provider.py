"""
Demo/Mock Intelligence Provider - Fallback when external APIs unavailable
Generates realistic but clearly marked DEMO data for testing and development
"""
import random
from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone
from app.intelligence.base import IntelligenceProvider
from app.schemas import IPIntelligenceData, DomainIntelligenceData


class DemoIntelligenceProvider(IntelligenceProvider):
    """
    Demo provider that generates realistic intelligence data.
    All responses are marked with is_demo=True flag.
    Used as fallback when external APIs are unavailable.
    """

    DEMO_COUNTRIES = [
        {"name": "United States", "code": "US", "regions": ["California", "New York", "Texas"]},
        {"name": "China", "code": "CN", "regions": ["Beijing", "Shanghai", "Guangdong"]},
        {"name": "Russia", "code": "RU", "regions": ["Moscow", "Saint Petersburg", "Novosibirsk"]},
        {"name": "India", "code": "IN", "regions": ["Maharashtra", "Karnataka", "Delhi"]},
        {"name": "United Kingdom", "code": "GB", "regions": ["England", "Scotland", "Wales"]},
        {"name": "Germany", "code": "DE", "regions": ["Bavaria", "Berlin", "Hamburg"]},
        {"name": "Nigeria", "code": "NG", "regions": ["Lagos", "Abuja", "Rivers"]},
        {"name": "Brazil", "code": "BR", "regions": ["São Paulo", "Rio de Janeiro", "Bahia"]},
    ]

    DEMO_ISPS = [
        "Amazon Web Services", "Google Cloud", "Microsoft Azure", "DigitalOcean",
        "OVH", "Hetzner", "Linode", "Vultr", "China Telecom", "Comcast",
        "AT&T", "Verizon", "Deutsche Telekom", "Orange", "Vodafone"
    ]

    SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".review"]
    LEGITIMATE_TLDS = [".com", ".org", ".net", ".edu", ".gov", ".io"]

    def __init__(self):
        super().__init__(api_key="DEMO_MODE")
        self.provider_name = "DemoProvider"

    async def get_ip_intelligence(self, ip_address: str) -> Optional[IPIntelligenceData]:
        """Generate demo IP intelligence data"""

        # Determine if this IP should be flagged as suspicious
        # Use last octet to create deterministic but varied results
        last_octet = int(ip_address.split('.')[-1])
        is_suspicious = last_octet > 200
        is_proxy = last_octet % 10 == 0
        is_vpn = last_octet % 7 == 0
        is_hosting = last_octet % 3 == 0

        # Pick a country
        country_data = random.choice(self.DEMO_COUNTRIES)
        region = random.choice(country_data["regions"])

        # Generate reputation score (lower for suspicious IPs)
        if is_suspicious:
            reputation_score = random.uniform(20, 50)
            abuse_confidence = random.uniform(60, 95)
            total_reports = random.randint(5, 50)
        else:
            reputation_score = random.uniform(70, 95)
            abuse_confidence = random.uniform(0, 20)
            total_reports = random.randint(0, 2)

        # Generate coordinates
        lat = random.uniform(-90, 90)
        lon = random.uniform(-180, 180)

        isp = random.choice(self.DEMO_ISPS)
        asn = f"AS{random.randint(1000, 99999)}"

        return IPIntelligenceData(
            ip_address=ip_address,
            country=country_data["name"],
            country_code=country_data["code"],
            region=region,
            city=f"Demo City {random.randint(1, 100)}",
            latitude=round(lat, 6),
            longitude=round(lon, 6),
            isp=isp,
            asn=asn,
            organization=isp,
            is_hosting=is_hosting,
            is_proxy=is_proxy,
            is_vpn=is_vpn,
            is_tor=False,
            reputation_score=round(reputation_score, 2),
            is_malicious=is_suspicious,
            abuse_confidence_score=round(abuse_confidence, 2) if is_suspicious else None,
            total_reports=total_reports if total_reports > 0 else None,
            provider="DemoProvider",
            context_note="DEMO DATA: Geolocation is contextual intelligence and does not establish physical attribution.",
            is_demo=True
        )

    async def get_domain_intelligence(self, domain: str) -> Optional[DomainIntelligenceData]:
        """Generate demo domain intelligence data"""

        domain_lower = domain.lower()

        # Extract TLD
        tld = "." + domain_lower.split(".")[-1] if "." in domain_lower else ""

        # Determine if suspicious
        is_suspicious_tld = tld in self.SUSPICIOUS_TLDS
        has_numbers = any(c.isdigit() for c in domain_lower)
        is_long = len(domain_lower) > 30

        is_suspicious = is_suspicious_tld or (has_numbers and is_long)
        is_malicious = is_suspicious and random.random() > 0.5

        # Check for lookalikes
        is_lookalike = False
        lookalike_target = None
        common_brands = ["paypal", "amazon", "microsoft", "google", "apple", "netflix"]
        for brand in common_brands:
            if brand in domain_lower and domain_lower != f"{brand}.com":
                is_lookalike = True
                lookalike_target = f"{brand}.com"
                break

        # Generate domain age
        if is_suspicious:
            creation_date = datetime.now(timezone.utc) - timedelta(days=random.randint(1, 90))
            domain_age_days = random.randint(1, 90)
        else:
            creation_date = datetime.now(timezone.utc) - timedelta(days=random.randint(365, 3650))
            domain_age_days = random.randint(365, 3650)

        # Reputation score
        if is_malicious:
            reputation_score = random.uniform(10, 40)
            threat_types = ["phishing", "malware"]
        elif is_suspicious:
            reputation_score = random.uniform(40, 60)
            threat_types = ["suspicious"]
        else:
            reputation_score = random.uniform(70, 95)
            threat_types = []

        return DomainIntelligenceData(
            domain=domain,
            tld=tld,
            registrar=random.choice(["GoDaddy", "Namecheap", "Google Domains", "Cloudflare"]),
            creation_date=creation_date,
            domain_age_days=domain_age_days,
            is_malicious=is_malicious,
            is_suspicious=is_suspicious,
            is_lookalike=is_lookalike,
            lookalike_target=lookalike_target,
            has_suspicious_tld=is_suspicious_tld,
            reputation_score=round(reputation_score, 2),
            threat_types=threat_types,
            provider="DemoProvider",
            is_demo=True
        )

    async def get_url_reputation(self, url: str) -> Optional[Dict[str, Any]]:
        """Generate demo URL reputation data"""

        url_lower = url.lower()

        is_suspicious = any(pattern in url_lower for pattern in ["bit.ly", "tinyurl", "login", "verify", "secure"])
        is_malicious = is_suspicious and random.random() > 0.6

        if is_malicious:
            reputation_score = random.uniform(10, 35)
            threat_categories = ["phishing", "malware"]
        elif is_suspicious:
            reputation_score = random.uniform(40, 60)
            threat_categories = ["suspicious"]
        else:
            reputation_score = random.uniform(70, 95)
            threat_categories = []

        return {
            "url": url,
            "reputation_score": round(reputation_score, 2),
            "is_malicious": is_malicious,
            "is_suspicious": is_suspicious,
            "threat_categories": threat_categories,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "provider": "DemoProvider",
            "is_demo": True,
            "note": "DEMO DATA - Not real threat intelligence"
        }

    async def get_file_reputation(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Generate demo file reputation data"""

        # Use hash to create deterministic results
        hash_int = int(file_hash[:8], 16) if file_hash else 0
        is_malicious = hash_int % 10 > 7  # 20% chance of being flagged

        if is_malicious:
            detection_count = random.randint(5, 30)
            threat_names = ["Trojan.Generic", "Malware.Unknown", "Phishing.Document"]
        else:
            detection_count = 0
            threat_names = []

        return {
            "hash": file_hash,
            "is_malicious": is_malicious,
            "detection_count": detection_count,
            "total_engines": 60,
            "threat_names": threat_names,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "provider": "DemoProvider",
            "is_demo": True,
            "note": "DEMO DATA - Not real threat intelligence"
        }

    async def is_available(self) -> bool:
        """Demo provider is always available"""
        return True
