"""
Threat Intelligence API Endpoints
"""
from fastapi import APIRouter, HTTPException, status
from app.intelligence.manager import threat_intelligence_manager
from app.schemas import IPIntelligenceData, DomainIntelligenceData

router = APIRouter(prefix="/api/v1/threat-intelligence", tags=["threat-intelligence"])


@router.get("/ip/{ip_address}", response_model=IPIntelligenceData)
async def get_ip_intelligence(ip_address: str):
    """
    Query geolocation, network, ASN, and reputation for an IP address.
    Uses configured external providers (VirusTotal, AbuseIPDB, IP-API) with automatic fallback.
    """
    try:
        data = await threat_intelligence_manager.get_ip_intelligence(ip_address)
        return data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"IP intelligence query failed: {str(e)}"
        )


@router.get("/domain/{domain}", response_model=DomainIntelligenceData)
async def get_domain_intelligence(domain: str):
    """
    Query domain reputation, registrar, age, lookalike analysis, and threat indicators.
    """
    try:
        data = await threat_intelligence_manager.get_domain_intelligence(domain)
        return data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Domain intelligence query failed: {str(e)}"
        )


@router.get("/url")
async def get_url_reputation(url: str):
    """
    Query URL reputation, redirection analysis, and threat categories.
    """
    try:
        data = await threat_intelligence_manager.get_url_reputation(url)
        return data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL reputation query failed: {str(e)}"
        )


@router.get("/hash/{file_hash}")
async def get_file_hash_reputation(file_hash: str):
    """
    Query file hash (SHA-256 / MD5) reputation across threat intelligence feeds.
    """
    try:
        data = await threat_intelligence_manager.get_file_reputation(file_hash)
        return data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File hash reputation query failed: {str(e)}"
        )
