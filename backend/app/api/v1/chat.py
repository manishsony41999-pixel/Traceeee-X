"""
TRACE-X AI SOC Analyst Copilot API
Provides interactive conversational cybersecurity assistance:
- Email authentication diagnostics (SPF, DKIM, DMARC)
- RFC 5322 header anomaly decoding and hop routing analysis
- NIST SP 800-61r2 incident containment and remediation playbooks
- Threat hunting query generation (KQL, Splunk SPL)
"""
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, status

from app.schemas import ChatMessage, ChatQueryRequest, ChatQueryResponse
from app.services.ai_analyzer import ai_analyzer
from app.config import settings

logger = logging.getLogger("tracex.chat")

router = APIRouter(prefix="/chat", tags=["chat"])


@router.post(
    "/query",
    response_model=ChatQueryResponse,
    summary="Query the AI SOC Analyst Copilot",
    status_code=status.HTTP_200_OK
)
async def query_soc_copilot(request: ChatQueryRequest) -> ChatQueryResponse:
    """
    Submits a conversational message sequence and optional active incident/email threat context
    to the TRACE-X AI SOC Analyst Copilot.
    """
    if not request.messages:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The 'messages' array cannot be empty. Please provide at least one message."
        )

    # Convert Pydantic message objects to standard dicts
    messages_payload: List[Dict[str, str]] = [
        {"role": m.role, "content": m.content}
        for m in request.messages
    ]

    try:
        response_text, suggested_actions, model_name = await ai_analyzer.answer_soc_copilot(
            messages=messages_payload,
            threat_context=request.threat_context
        )

        return ChatQueryResponse(
            response=response_text,
            role="assistant",
            model=model_name,
            threat_context_applied=bool(request.threat_context),
            suggested_actions=suggested_actions
        )
    except Exception as e:
        logger.error(f"Error executing SOC copilot query: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SOC Copilot query failed: {str(e)}"
        )


@router.get(
    "/status",
    summary="SOC Copilot service status and operational mode",
    status_code=status.HTTP_200_OK
)
async def get_copilot_status():
    """Returns Copilot operational readiness and active model provider configuration"""
    is_live_ai = bool(
        settings.AI_API_KEY
        and not settings.USE_DEMO_INTELLIGENCE
        and not settings.AI_API_KEY.startswith("sk-your-")
    )
    return {
        "status": "online",
        "service": "TRACE-X AI SOC Copilot",
        "configured_provider": settings.AI_PROVIDER,
        "configured_model": settings.AI_MODEL,
        "live_ai_available": is_live_ai,
        "offline_heuristic_fallback_ready": True,
        "supported_capabilities": [
            "SPF/DKIM/DMARC authentication diagnostics",
            "RFC 5322 header anomaly traversal",
            "NIST SP 800-61r2 4-phase containment playbooks",
            "Microsoft Sentinel / Defender KQL query generation",
            "Splunk SPL query generation",
            "Active incident IoC correlation"
        ]
    }
