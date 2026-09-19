"""
TRACE-X WebSocket Threat Stream Broadcast Channel
Provides real-time streaming of incoming email threat analyses (/api/v1/ws/threat-stream)
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Union

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel

from app.schemas import EmailAnalysisResponse

logger = logging.getLogger("tracex.threat_stream")

router = APIRouter(prefix="/api/v1/ws", tags=["threat-stream"])


class ThreatStreamChannel:
    """
    WebSocket Connection Manager and Broadcast Channel.
    Maintains active connections and broadcasts threat analysis events.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept new WebSocket connection and track in active connections"""
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"ThreatStream client connected. Active connections: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        """Safely remove disconnected WebSocket"""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"ThreatStream client disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast(self, message: Union[Dict[str, Any], str]) -> int:
        """
        Broadcast message payload to all active WebSocket clients.
        Automatically prunes disconnected clients.
        Returns number of successfully sent messages.
        """
        if isinstance(message, (dict, list)):
            payload = json.dumps(message, default=str)
        else:
            payload = str(message)

        async with self._lock:
            connections = list(self.active_connections)

        if not connections:
            logger.debug("No active WebSocket clients to receive broadcast.")
            return 0

        disconnected: List[WebSocket] = []
        sent_count = 0

        for ws in connections:
            try:
                await ws.send_text(payload)
                sent_count += 1
            except Exception as e:
                logger.warning(f"Failed to send to client {ws}: {e}")
                disconnected.append(ws)

        if disconnected:
            async with self._lock:
                for dead_ws in disconnected:
                    if dead_ws in self.active_connections:
                        self.active_connections.remove(dead_ws)

        logger.info(f"ThreatStream broadcast dispatched to {sent_count} client(s).")
        return sent_count

    async def broadcast_threat_analysis(
        self,
        analysis: Union[EmailAnalysisResponse, Dict[str, Any]],
        source: str = "google_workspace"
    ) -> int:
        """
        Push structured threat analysis into the WebSocket broadcast channel.
        """
        if isinstance(analysis, EmailAnalysisResponse):
            analysis_dict = analysis.model_dump(mode="json")
        elif hasattr(analysis, "model_dump"):
            analysis_dict = analysis.model_dump(mode="json")
        elif isinstance(analysis, dict):
            analysis_dict = analysis
        else:
            analysis_dict = {"raw": str(analysis)}

        event_payload = {
            "type": "threat_analysis",
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": analysis_dict
        }
        return await self.broadcast(event_payload)

    @property
    def client_count(self) -> int:
        return len(self.active_connections)


# Singleton broadcast channel instance
threat_stream_channel = ThreatStreamChannel()


@router.websocket("/threat-stream")
async def websocket_threat_stream_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time threat stream:
    URL: ws://{host}:{port}/api/v1/ws/threat-stream
    Pushes live forensic assessment results as emails arrive and are analyzed.
    """
    await threat_stream_channel.connect(websocket)
    try:
        # Send initial welcome / handshake event
        await websocket.send_json({
            "event": "connected",
            "channel": "/api/v1/ws/threat-stream",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "Connected to TRACE-X Real-Time Threat Stream"
        })

        while True:
            # Listen for client messages (e.g., ping/pong keepalive)
            text_data = await websocket.receive_text()
            stripped = text_data.strip()
            if stripped.lower() == "ping":
                await websocket.send_json({
                    "event": "pong",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            else:
                # Echo ack for client debugging
                await websocket.send_json({
                    "event": "ack",
                    "received": stripped
                })
    except WebSocketDisconnect:
        await threat_stream_channel.disconnect(websocket)
    except Exception as e:
        logger.debug(f"ThreatStream connection exception: {e}")
        await threat_stream_channel.disconnect(websocket)


class StreamStatusResponse(BaseModel):
    channel: str = "/api/v1/ws/threat-stream"
    active_connections: int
    status: str = "operational"


@router.get("/threat-stream/status", response_model=StreamStatusResponse)
async def get_threat_stream_status():
    """Check current WebSocket threat stream connection status"""
    return StreamStatusResponse(
        active_connections=threat_stream_channel.client_count
    )


class BroadcastTestRequest(BaseModel):
    message: str = "Test broadcast from TRACE-X"
    severity: str = "INFO"


@router.post("/threat-stream/broadcast-test")
async def broadcast_test_message(req: BroadcastTestRequest):
    """Trigger a test message broadcast to all connected WebSocket clients"""
    count = await threat_stream_channel.broadcast({
        "type": "system_broadcast",
        "message": req.message,
        "severity": req.severity,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    return {"status": "broadcast_sent", "recipients": count}
