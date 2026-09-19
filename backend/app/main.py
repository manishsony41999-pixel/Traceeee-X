"""
TRACE-X FastAPI Application
AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform
"""
from fastapi import FastAPI
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from app.config import settings
from app.database import init_db, close_db
from app.api.v1.emails import router as emails_router
from app.api.v1.cases import router as cases_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.intelligence import router as intelligence_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.webhooks import router as webhooks_router
from app.api.v1.threat_stream import router as threat_stream_router
from app.api.v1.chat import router as chat_router
from app.services.google_ingestion import mailbox_watch_manager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("tracex")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events"""
    logger.info("Initializing TRACE-X database...")
    try:
        await init_db()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.warning(f"Database connection warning (running in degraded or fallback mode): {e}")

    # Initialize Google Workspace Mailbox Watch Manager & renewal worker
    try:
        await mailbox_watch_manager.startup_register_watches()
        mailbox_watch_manager.start_renewal_loop()
        logger.info("Mailbox Watch Manager initialized and renewal worker started.")
    except Exception as e:
        logger.warning(f"Mailbox watch manager initialization warning: {e}")

    yield

    logger.info("Shutting down TRACE-X...")
    try:
        await mailbox_watch_manager.stop_renewal_loop()
    except Exception:
        pass
    try:
        await close_db()
    except Exception:
        pass


app = FastAPI(
    title="TRACE-X API",
    description="AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Setup CORS for Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(emails_router)
app.include_router(cases_router)
app.include_router(evidence_router)
app.include_router(intelligence_router)
app.include_router(dashboard_router)
app.include_router(webhooks_router)
app.include_router(threat_stream_router)
app.include_router(chat_router, prefix="/api/v1")
app.include_router(chat_router)
# Serve React frontend in production
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend" / "dist"

if FRONTEND_DIR.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=FRONTEND_DIR / "assets"),
        name="assets"
    )

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        file_path = FRONTEND_DIR / full_path

        if file_path.is_file():
            return FileResponse(file_path)

        return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/")
async def root():
    """Root status endpoint"""
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "mode": "Demonstration & Forensic Analysis",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "ai_provider": settings.AI_PROVIDER,
        "demo_mode": settings.USE_DEMO_INTELLIGENCE
    }
# Serve React frontend in production
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend" / "dist"

if FRONTEND_DIR.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=FRONTEND_DIR / "assets"),
        name="assets"
    )

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        file_path = FRONTEND_DIR / full_path

        if file_path.is_file():
            return FileResponse(file_path)

        return FileResponse(FRONTEND_DIR / "index.html")