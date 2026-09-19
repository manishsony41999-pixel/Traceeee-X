"""
TRACE-X Google Cloud Pub/Sub Webhook Endpoints
Handles incoming Google Cloud Pub/Sub push notifications for real-time Gmail ingestion:
- Decodes base64 payload to extract user email and historyId
- Triggers message ingestion and threat analysis
- Manages mailbox watch subscriptions
"""
import base64
import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field

from app.config import settings
from app.services.google_ingestion import google_ingestion_service, mailbox_watch_manager
from app.schemas import EmailAnalysisResponse

logger = logging.getLogger("tracex.webhooks")

router = APIRouter(prefix="/api/v1", tags=["webhooks"])


# =====================================================================
# Pydantic Schemas for Pub/Sub Webhook
# =====================================================================

class PubSubMessageData(BaseModel):
    data: Optional[str] = None
    messageId: Optional[str] = None
    publishTime: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None


class PubSubPushRequest(BaseModel):
    message: Optional[PubSubMessageData] = None
    subscription: Optional[str] = None
    # Support direct un-enveloped testing payloads
    emailAddress: Optional[str] = None
    email: Optional[str] = None
    historyId: Optional[Any] = None


class WebhookResponse(BaseModel):
    status: str
    user_email: Optional[str] = None
    history_id: Optional[str] = None
    message: str
    results: Optional[List[Dict[str, Any]]] = None


class WatchMailboxRequest(BaseModel):
    email: str
    topic_name: Optional[str] = None
    label_ids: Optional[List[str]] = Field(default=["INBOX"])


class StopWatchRequest(BaseModel):
    email: str


class SimulateIngestionRequest(BaseModel):
    user_email: str = "security-demo@example.com"
    raw_email: str
    broadcast_websocket: bool = True


# =====================================================================
# Helper Functions
# =====================================================================

def decode_pubsub_base64(raw_b64: str) -> Dict[str, Any]:
    """
    Safely decode Base64 / URL-safe Base64 Pub/Sub payload.
    Recovers missing padding and parses inner JSON data.
    """
    clean_str = raw_b64.strip()
    missing_padding = len(clean_str) % 4
    if missing_padding:
        clean_str += "=" * (4 - missing_padding)

    try:
        decoded_bytes = base64.b64decode(clean_str)
    except Exception:
        decoded_bytes = base64.urlsafe_b64decode(clean_str)

    decoded_text = decoded_bytes.decode("utf-8")
    return json.loads(decoded_text)


def extract_pubsub_credentials(payload_dict: Dict[str, Any]) -> tuple[str, str]:
    """
    Extract user email and historyId from parsed Pub/Sub push JSON.
    Handles both standard Pub/Sub envelope and direct payloads.
    """
    email = None
    history_id = None

    # Case 1: Standard Pub/Sub push envelope {"message": {"data": "..."}}
    msg = payload_dict.get("message")
    if isinstance(msg, dict) and msg.get("data"):
        try:
            inner_data = decode_pubsub_base64(msg["data"])
            email = inner_data.get("emailAddress") or inner_data.get("email")
            history_id = inner_data.get("historyId")
        except Exception as e:
            logger.error(f"Failed to decode base64 Pub/Sub payload: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 Pub/Sub message data: {str(e)}"
            )

    # Case 2: Direct payload {"emailAddress": "...", "historyId": "..."}
    if not email:
        email = payload_dict.get("emailAddress") or payload_dict.get("email")
    if not history_id:
        history_id = payload_dict.get("historyId")

    # Case 3: If message object had attributes
    if not email and isinstance(msg, dict) and msg.get("attributes"):
        attrs = msg["attributes"]
        email = attrs.get("emailAddress") or attrs.get("email")
        history_id = history_id or attrs.get("historyId")

    if not email or history_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Missing required fields: emailAddress/email and historyId in Pub/Sub payload."
        )

    return str(email), str(history_id)


# =====================================================================
# Webhook Endpoints
# =====================================================================

@router.post(
    "/webhook/google-pubsub",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="Handle incoming Google Cloud Pub/Sub push messages for Gmail"
)
@router.post(
    "/webhooks/google-pubsub",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False
)
async def handle_google_pubsub_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    sync: bool = Query(default=False, description="Wait synchronously for analysis to complete (useful for tests/demos)")
):
    """
    Endpoint: `POST /api/v1/webhook/google-pubsub`
    1. Validates optional verification token if configured.
    2. Decodes base64 Google Pub/Sub message payload to extract `historyId` and user email.
    3. Triggers Gmail ingestion pipeline to fetch new messages and perform threat analysis.
    4. Automatically pushes forensic analysis to `/api/v1/ws/threat-stream`.
    """
    # Optional shared secret verification
    if settings.GOOGLE_PUBSUB_VERIFICATION_TOKEN:
        token = request.query_params.get("token") or request.headers.get("X-Goog-Pubsub-Token")
        if token != settings.GOOGLE_PUBSUB_VERIFICATION_TOKEN:
            logger.warning("Pub/Sub push request rejected: invalid verification token.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing Pub/Sub verification token."
            )

    # Read raw JSON body
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload received."
        )

    # Extract email and historyId
    user_email, history_id = extract_pubsub_credentials(body)
    logger.info(f"Received Google Pub/Sub push notification for [{user_email}] - historyId: [{history_id}]")

    # If synchronous execution requested (e.g. tests or simulation)
    if sync:
        try:
            analyses = await google_ingestion_service.process_history_notification(
                user_email=user_email,
                history_id=history_id
            )
            serialized = [
                a.model_dump(mode="json") if hasattr(a, "model_dump") else a
                for a in analyses
            ]
            return WebhookResponse(
                status="completed",
                user_email=user_email,
                history_id=history_id,
                message=f"Successfully analyzed {len(analyses)} email(s) synchronously.",
                results=serialized
            )
        except Exception as e:
            logger.error(f"Synchronous ingestion failed for {user_email}: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Ingestion failed: {str(e)}"
            )

    # Production default: schedule in background task so Pub/Sub receives immediate 200 OK
    background_tasks.add_task(
        google_ingestion_service.process_history_notification,
        user_email,
        history_id
    )

    return WebhookResponse(
        status="accepted",
        user_email=user_email,
        history_id=history_id,
        message="Pub/Sub notification received and queued for background ingestion."
    )


# =====================================================================
# Mailbox Watch Management & Status Endpoints
# =====================================================================

@router.get(
    "/webhook/google-pubsub/status",
    summary="Get operational status of Google Workspace ingestion and watch manager"
)
async def get_google_ingestion_status():
    """Returns current status of mailbox watch manager, watched accounts, and renewals"""
    return {
        "status": "operational",
        "watch_manager": mailbox_watch_manager.get_status(),
        "topic": settings.GOOGLE_PUBSUB_TOPIC,
        "active_watched_count": len(mailbox_watch_manager.watched_mailboxes)
    }


@router.post(
    "/webhook/google-pubsub/watch",
    summary="Register Gmail watch for an email address"
)
async def register_mailbox_watch(req: WatchMailboxRequest):
    """
    Manually register users().watch() for an email address with GCP Pub/Sub.
    """
    try:
        watch_info = await mailbox_watch_manager.register_watch(
            user_email=req.email,
            topic_name=req.topic_name,
            label_ids=req.label_ids
        )
        return {"status": "watch_registered", "watch_info": watch_info}
    except Exception as e:
        logger.error(f"Failed to register watch for {req.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Watch registration failed: {str(e)}"
        )


@router.post(
    "/webhook/google-pubsub/stop-watch",
    summary="Stop Gmail watch for an email address"
)
async def stop_mailbox_watch(req: StopWatchRequest):
    """
    Cancel push notifications by calling users().stop().
    """
    try:
        await mailbox_watch_manager.stop_watch(user_email=req.email)
        return {"status": "watch_stopped", "email": req.email}
    except Exception as e:
        logger.error(f"Failed to stop watch for {req.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Stopping watch failed: {str(e)}"
        )


@router.post(
    "/webhook/google-pubsub/renew",
    summary="Trigger immediate watch renewal check"
)
async def trigger_watch_renewal(hours: int = Query(default=48)):
    """
    Forces immediate renewal check for all active mailboxes expiring within given hours.
    """
    renewed = await mailbox_watch_manager.renew_expiring_watches(renewal_window_hours=hours)
    return {"status": "renewal_completed", "renewed_mailboxes": renewed}


@router.post(
    "/webhook/google-pubsub/simulate",
    summary="Simulate raw email ingestion and broadcast to WebSocket threat stream"
)
async def simulate_google_ingestion(req: SimulateIngestionRequest):
    """
    Convenience endpoint for development & testing:
    Directly passes raw RFC 822 email bytes into the ingestion pipeline and broadcasts to threat-stream.
    """
    try:
        raw_bytes = req.raw_email.encode("utf-8")
        analysis = await google_ingestion_service.process_raw_email_bytes(
            raw_bytes=raw_bytes,
            source=f"simulate:{req.user_email}"
        )
        return {
            "status": "ingested",
            "email_id": analysis.email_id,
            "risk_score": analysis.risk_score,
            "severity": analysis.severity,
            "is_malicious": analysis.is_malicious,
            "threat_type": analysis.threat_type,
            "analysis": analysis.model_dump(mode="json")
        }
    except Exception as e:
        logger.error(f"Simulation failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Simulation ingestion failed: {str(e)}"
        )
