"""
TRACE-X Google Workspace & Gmail Real-Time Ingestion Service
Handles:
1. Authenticated Gmail API connectivity (Domain-Wide Delegation / OAuth2 / Service Account).
2. Fetching raw RFC 822 MIME messages with `users().messages().get(userId=..., id=..., format='raw')`.
3. Decoding raw bytes and passing directly into `email_analysis_orchestrator.py`.
4. Broadcasting threat analysis results to `/api/v1/ws/threat-stream`.
5. Mailbox Watch Manager for registering `users().watch()` with GCP Pub/Sub and renewing before 7-day expiration.
"""
import asyncio
import base64
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Union
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import AsyncSessionLocal
from app.services.email_analysis_orchestrator import EmailAnalysisOrchestrator
from app.api.v1.threat_stream import threat_stream_channel
from app.schemas import EmailAnalysisResponse

# Optional Google API client imports with graceful degradation
try:
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
    from google.oauth2 import service_account
    from google.oauth2.credentials import Credentials as OAuthCredentials
    GOOGLE_CLIENT_AVAILABLE = True
except ImportError:
    GOOGLE_CLIENT_AVAILABLE = False
    build = None
    HttpError = Exception
    service_account = None
    OAuthCredentials = None

logger = logging.getLogger("tracex.google_ingestion")

# Gmail Read-Only Scope
GMAIL_READONLY_SCOPE = ["https://www.googleapis.com/auth/gmail.readonly"]


class GoogleIngestionService:
    """
    Service responsible for Gmail API integration, message retrieval,
    raw RFC 822 MIME ingestion, and dispatching to analysis orchestrator.
    """

    def __init__(self):
        self._history_state: Dict[str, int] = {}  # Tracks last known historyId per mailbox
        self._service_cache: Dict[str, Any] = {}
        self._lock = asyncio.Lock()

    def has_credentials(self) -> bool:
        """Check if any Google Cloud service account credentials are provided"""
        return bool(settings.GOOGLE_APPLICATION_CREDENTIALS or settings.GOOGLE_SERVICE_ACCOUNT_INFO)

    def get_gmail_service(self, user_email: str, credentials_override: Optional[Any] = None) -> Any:
        """
        Builds an authenticated Google Gmail API service resource for the specified user email.
        Supports:
        - Domain-Wide Delegation (DWD) using a GCP Service Account
        - Direct Credentials object override
        - Environment variable JSON string (GOOGLE_SERVICE_ACCOUNT_INFO)
        - Service account file path (GOOGLE_APPLICATION_CREDENTIALS)
        """
        if credentials_override:
            return build("gmail", "v1", credentials=credentials_override, cache_discovery=False)

        if not GOOGLE_CLIENT_AVAILABLE:
            raise RuntimeError(
                "google-api-python-client is not installed. "
                "Please install google-api-python-client, google-auth, and google-auth-oauthlib."
            )

        # Check cache
        if user_email in self._service_cache:
            return self._service_cache[user_email]

        creds = None

        # 1. Check GOOGLE_SERVICE_ACCOUNT_INFO (JSON string)
        if settings.GOOGLE_SERVICE_ACCOUNT_INFO:
            try:
                info = json.loads(settings.GOOGLE_SERVICE_ACCOUNT_INFO)
                sa_creds = service_account.Credentials.from_service_account_info(
                    info,
                    scopes=GMAIL_READONLY_SCOPE
                )
                creds = sa_creds.with_subject(user_email)
                logger.info(f"Loaded GCP credentials from GOOGLE_SERVICE_ACCOUNT_INFO with subject: {user_email}")
            except Exception as e:
                logger.error(f"Failed to load GOOGLE_SERVICE_ACCOUNT_INFO: {e}")

        # 2. Check GOOGLE_APPLICATION_CREDENTIALS (file path)
        if not creds and settings.GOOGLE_APPLICATION_CREDENTIALS:
            try:
                sa_creds = service_account.Credentials.from_service_account_file(
                    settings.GOOGLE_APPLICATION_CREDENTIALS,
                    scopes=GMAIL_READONLY_SCOPE
                )
                creds = sa_creds.with_subject(user_email)
                logger.info(f"Loaded GCP credentials from {settings.GOOGLE_APPLICATION_CREDENTIALS} with subject: {user_email}")
            except Exception as e:
                logger.error(f"Failed to load GOOGLE_APPLICATION_CREDENTIALS: {e}")

        if not creds:
            raise ValueError(
                f"No Google API credentials configured for {user_email}. "
                "Configure GOOGLE_APPLICATION_CREDENTIALS or GOOGLE_SERVICE_ACCOUNT_INFO."
            )

        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        self._service_cache[user_email] = service
        return service

    @staticmethod
    def decode_raw_mime(raw_b64: str) -> bytes:
        """
        Decode base64url encoded raw RFC 822 MIME string from Gmail API.
        Handles missing padding and URL-safe replacements.
        """
        # Ensure padding
        missing_padding = len(raw_b64) % 4
        if missing_padding:
            raw_b64 += "=" * (4 - missing_padding)
        return base64.urlsafe_b64decode(raw_b64.encode("utf-8"))

    async def fetch_and_analyze_message(
        self,
        user_email: str,
        message_id: str,
        db: Optional[AsyncSession] = None,
        gmail_service: Optional[Any] = None
    ) -> EmailAnalysisResponse:
        """
        1. Fetch raw RFC 822 MIME message using `gmail.users().messages().get(userId=..., id=..., format='raw')`
        2. Decode raw base64url string to raw bytes
        3. Pass decoded raw bytes directly into `email_analysis_orchestrator.py`
        4. Broadcast analysis results to the WebSocket broadcast channel (`/api/v1/ws/threat-stream`)
        """
        service = gmail_service or self.get_gmail_service(user_email)

        logger.info(f"Fetching raw RFC 822 MIME message [ID: {message_id}] for user [{user_email}]...")
        # Execute blocking Google API client call in threadpool
        msg_data = await asyncio.to_thread(
            lambda: service.users().messages().get(userId=user_email, id=message_id, format="raw").execute()
        )

        raw_b64 = msg_data.get("raw")
        if not raw_b64:
            raise ValueError(f"Gmail API returned empty raw body for message {message_id}")

        # Decode base64url to raw RFC 822 MIME bytes
        raw_bytes = self.decode_raw_mime(raw_b64)
        logger.info(f"Successfully retrieved and decoded {len(raw_bytes)} raw bytes for message {message_id}")

        # Pass decoded raw bytes directly into email_analysis_orchestrator.py
        return await self.process_raw_email_bytes(
            raw_bytes=raw_bytes,
            db=db,
            source=f"gmail:{user_email}",
            message_id=message_id
        )

    async def process_raw_email_bytes(
        self,
        raw_bytes: bytes,
        db: Optional[AsyncSession] = None,
        source: str = "google_workspace",
        message_id: Optional[str] = None
    ) -> EmailAnalysisResponse:
        """
        Ingest raw bytes into EmailAnalysisOrchestrator and broadcast
        to WebSocket threat-stream.
        """
        logger.info(f"Orchestrating forensic analysis for raw email bytes ({len(raw_bytes)} bytes)...")

        # Execute analysis pipeline
        if db is not None:
            analysis_result = await EmailAnalysisOrchestrator.analyze_email(
                db=db,
                raw_email_content=raw_bytes,
                source=source
            )
        else:
            try:
                async with AsyncSessionLocal() as session:
                    analysis_result = await EmailAnalysisOrchestrator.analyze_email(
                        db=session,
                        raw_email_content=raw_bytes,
                        source=source
                    )
            except Exception as db_err:
                logger.warning(f"Database session unavailable, analyzing without DB persistence: {db_err}")
                analysis_result = await EmailAnalysisOrchestrator.analyze_email(
                    db=None,
                    raw_email_content=raw_bytes,
                    source=source
                )

        logger.info(
            f"Analysis complete for email {analysis_result.email_id}: "
            f"Risk={analysis_result.risk_score} Severity={analysis_result.severity} Malicious={analysis_result.is_malicious}"
        )

        # Push analysis results into WebSocket broadcast channel (/api/v1/ws/threat-stream)
        try:
            broadcast_count = await threat_stream_channel.broadcast_threat_analysis(
                analysis=analysis_result,
                source=source
            )
            logger.info(f"Pushed analysis {analysis_result.email_id} to {broadcast_count} WebSocket client(s).")
        except Exception as ws_err:
            logger.warning(f"Failed to broadcast analysis to WebSocket threat-stream: {ws_err}")

        return analysis_result

    async def process_history_notification(
        self,
        user_email: str,
        history_id: Union[str, int],
        db: Optional[AsyncSession] = None,
        gmail_service: Optional[Any] = None
    ) -> List[EmailAnalysisResponse]:
        """
        Handle incoming Gmail history notification from Pub/Sub push.
        Determines new messages added since previous historyId and analyzes them.
        """
        new_history_id = int(history_id)
        last_history_id = self._history_state.get(user_email)
        try:
            service = gmail_service or self.get_gmail_service(user_email)
        except Exception as cred_err:
            logger.warning(f"Gmail API credentials not configured for {user_email}: {cred_err}")
            return []

        message_ids: List[str] = []

        if last_history_id and last_history_id < new_history_id:
            try:
                logger.info(f"Querying Gmail history list for {user_email} from historyId {last_history_id}...")
                history_resp = await asyncio.to_thread(
                    lambda: service.users().history().list(
                        userId=user_email,
                        startHistoryId=str(last_history_id),
                        historyTypes=["messageAdded"]
                    ).execute()
                )

                for record in history_resp.get("history", []):
                    for msg_added in record.get("messagesAdded", []):
                        msg = msg_added.get("message", {})
                        if "id" in msg:
                            message_ids.append(msg["id"])
            except Exception as hist_err:
                logger.warning(f"Gmail history query failed ({hist_err}), falling back to recent inbox messages.")

        # Fallback: if history list was not applicable (e.g. initial sync or history expired)
        if not message_ids:
            try:
                logger.info(f"Fetching most recent inbox messages for {user_email}...")
                list_resp = await asyncio.to_thread(
                    lambda: service.users().messages().list(
                        userId=user_email,
                        maxResults=5,
                        labelIds=["INBOX"]
                    ).execute()
                )
                for msg_summary in list_resp.get("messages", []):
                    message_ids.append(msg_summary["id"])
            except Exception as list_err:
                logger.error(f"Failed to list messages for {user_email}: {list_err}")

        # Update last known historyId
        self._history_state[user_email] = new_history_id

        # Deduplicate while preserving order
        unique_ids = list(dict.fromkeys(message_ids))
        logger.info(f"Found {len(unique_ids)} message(s) to ingest for {user_email}: {unique_ids}")

        results: List[EmailAnalysisResponse] = []
        for mid in unique_ids:
            try:
                analysis = await self.fetch_and_analyze_message(
                    user_email=user_email,
                    message_id=mid,
                    db=db,
                    gmail_service=service
                )
                results.append(analysis)
            except Exception as e:
                logger.error(f"Failed to ingest and analyze message {mid} for {user_email}: {e}", exc_info=True)

        return results


class MailboxWatchManager:
    """
    Mailbox Watch Manager:
    1. Registers `users().watch()` with Google Cloud Pub/Sub topic.
    2. Maintains active watch expiration timestamps.
    3. Runs a background loop to renew watches periodically before the 7-day expiration.
    """

    def __init__(self, ingestion_service: GoogleIngestionService):
        self.ingestion_service = ingestion_service
        self.watched_mailboxes: Dict[str, Dict[str, Any]] = {}
        self._renewal_task: Optional[asyncio.Task] = None
        self._running: bool = False

    async def register_watch(
        self,
        user_email: str,
        topic_name: Optional[str] = None,
        label_ids: Optional[List[str]] = None,
        gmail_service: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Calls `gmail.users().watch(userId=..., body={...})` to register push notifications with GCP Pub/Sub.
        Returns watch metadata including expiration timestamp and historyId.
        Falls back gracefully to simulated/demo watch registration if GCP credentials or topic are not configured.
        """
        topic = topic_name or settings.GOOGLE_PUBSUB_TOPIC or "projects/tracex-demo/topics/gmail-inbox-watch"
        labels = label_ids if label_ids is not None else settings.GMAIL_WATCH_LABEL_IDS or ["INBOX"]

        # Check whether live GCP credentials or explicit mock service are present
        has_real_creds = gmail_service is not None or self.ingestion_service.has_credentials()

        if not has_real_creds:
            if not settings.USE_DEMO_INTELLIGENCE and not topic_name:
                raise ValueError(
                    "Google Pub/Sub credentials not configured and USE_DEMO_INTELLIGENCE is false. "
                    "Configure GOOGLE_APPLICATION_CREDENTIALS or GOOGLE_SERVICE_ACCOUNT_INFO in backend/.env."
                )

            # Register simulated/demo watch
            simulated_history_id = self.ingestion_service._history_state.get(
                user_email, 100000 + abs(hash(user_email)) % 900000
            )
            expiration_dt = datetime.now(timezone.utc) + timedelta(days=7)
            expiration_ms = int(expiration_dt.timestamp() * 1000)

            watch_info = {
                "user_email": user_email,
                "topic_name": topic,
                "label_ids": labels,
                "history_id": str(simulated_history_id),
                "expiration_ms": expiration_ms,
                "expiration": expiration_dt.isoformat(),
                "status": "active (demo mode)",
                "is_simulated": True,
                "last_renewed": datetime.now(timezone.utc).isoformat()
            }

            self.watched_mailboxes[user_email] = watch_info
            self.ingestion_service._history_state[user_email] = simulated_history_id

            logger.info(
                f"[Demo Mode] Successfully registered simulated Gmail watch for {user_email} on topic {topic}. "
                f"Expires at: {expiration_dt}"
            )
            return watch_info

        service = gmail_service or self.ingestion_service.get_gmail_service(user_email)

        watch_body = {
            "topicName": topic,
            "labelIds": labels,
            "labelFilterAction": "include"
        }

        logger.info(f"Registering Gmail watch for {user_email} on topic {topic} with labels {labels}...")
        response = await asyncio.to_thread(
            lambda: service.users().watch(userId=user_email, body=watch_body).execute()
        )

        history_id = response.get("historyId")
        expiration_ms = int(response.get("expiration", 0))
        expiration_dt = datetime.fromtimestamp(expiration_ms / 1000, tz=timezone.utc) if expiration_ms else None

        watch_info = {
            "user_email": user_email,
            "topic_name": topic,
            "label_ids": labels,
            "history_id": str(history_id) if history_id else None,
            "expiration_ms": expiration_ms,
            "expiration": expiration_dt.isoformat() if expiration_dt else None,
            "status": "active",
            "is_simulated": False,
            "last_renewed": datetime.now(timezone.utc).isoformat()
        }

        self.watched_mailboxes[user_email] = watch_info
        if history_id:
            self.ingestion_service._history_state[user_email] = int(history_id)

        logger.info(f"Successfully registered Gmail watch for {user_email}. Expires at: {expiration_dt}")
        return watch_info

    async def stop_watch(self, user_email: str, gmail_service: Optional[Any] = None) -> bool:
        """
        Calls `gmail.users().stop(userId=...)` to disable push notifications.
        """
        has_real_creds = gmail_service is not None or self.ingestion_service.has_credentials()
        if has_real_creds:
            try:
                service = gmail_service or self.ingestion_service.get_gmail_service(user_email)
                logger.info(f"Stopping Gmail watch for {user_email}...")
                await asyncio.to_thread(
                    lambda: service.users().stop(userId=user_email).execute()
                )
            except Exception as e:
                logger.warning(f"Error calling Gmail users().stop() for {user_email}: {e}")
        else:
            logger.info(f"[Demo Mode] Stopped simulated Gmail watch for {user_email}")

        if user_email in self.watched_mailboxes:
            self.watched_mailboxes[user_email]["status"] = "stopped"
        return True

    async def renew_expiring_watches(
        self,
        renewal_window_hours: int = 48,
        gmail_service: Optional[Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Iterates all tracked mailboxes and renews any watch expiring within the renewal window
        or active mailboxes needing periodic refresh before the 7-day Gmail limit.
        """
        now = datetime.now(timezone.utc)
        renewed: List[Dict[str, Any]] = []

        for email, info in list(self.watched_mailboxes.items()):
            if info.get("status") != "active":
                continue

            exp_ms = info.get("expiration_ms", 0)
            exp_dt = datetime.fromtimestamp(exp_ms / 1000, tz=timezone.utc) if exp_ms else None

            should_renew = True
            if exp_dt:
                hours_left = (exp_dt - now).total_seconds() / 3600
                should_renew = hours_left <= renewal_window_hours

            if should_renew:
                try:
                    logger.info(f"Renewing Gmail watch for {email} (hours left: {hours_left if exp_dt else 'unknown'})...")
                    updated = await self.register_watch(
                        user_email=email,
                        topic_name=info.get("topic_name"),
                        label_ids=info.get("label_ids"),
                        gmail_service=gmail_service
                    )
                    renewed.append(updated)
                except Exception as e:
                    logger.error(f"Failed to renew Gmail watch for {email}: {e}")

        return renewed

    async def _renewal_worker(self):
        """
        Background task: periodically checks and renews watches.
        Runs hourly and ensures mailboxes are refreshed well ahead of 7-day expiry.
        """
        logger.info("Mailbox Watch Manager periodic renewal worker started.")
        # Check every hour
        check_interval_seconds = 3600

        while self._running:
            try:
                await asyncio.sleep(check_interval_seconds)
                if self._running:
                    await self.renew_expiring_watches(renewal_window_hours=48)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in mailbox watch renewal worker: {e}", exc_info=True)

        logger.info("Mailbox Watch Manager periodic renewal worker exited.")

    def start_renewal_loop(self):
        """Start the background renewal task"""
        if not self._running:
            self._running = True
            self._renewal_task = asyncio.create_task(self._renewal_worker())

    async def stop_renewal_loop(self):
        """Cancel and clean up the background renewal task"""
        self._running = False
        if self._renewal_task:
            self._renewal_task.cancel()
            try:
                await self._renewal_task
            except asyncio.CancelledError:
                pass
            self._renewal_task = None

    async def startup_register_watches(self):
        """
        Startup routine: Automatically registers watches for users configured
        in GMAIL_WATCH_USERS.
        """
        if not settings.GOOGLE_PUBSUB_TOPIC and not settings.USE_DEMO_INTELLIGENCE:
            logger.info("GOOGLE_PUBSUB_TOPIC not configured. Skipping automatic watch registration.")
            return

        if not settings.GMAIL_WATCH_USERS:
            logger.info("No mailboxes in GMAIL_WATCH_USERS. Mailbox watch manager initialized in idle mode.")
            return

        logger.info(f"Registering Gmail watches on startup for {len(settings.GMAIL_WATCH_USERS)} mailbox(es)...")
        for user_email in settings.GMAIL_WATCH_USERS:
            try:
                await self.register_watch(user_email=user_email)
            except Exception as e:
                logger.warning(f"Could not register Gmail watch for {user_email} on startup: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Return operational status and metadata for all watched mailboxes"""
        return {
            "worker_running": self._running,
            "pubsub_topic": settings.GOOGLE_PUBSUB_TOPIC,
            "renewal_interval_hours": settings.GMAIL_WATCH_RENEWAL_INTERVAL_HOURS,
            "total_watched_mailboxes": len(self.watched_mailboxes),
            "mailboxes": self.watched_mailboxes
        }


# Global service and watch manager singletons
google_ingestion_service = GoogleIngestionService()
mailbox_watch_manager = MailboxWatchManager(google_ingestion_service)
