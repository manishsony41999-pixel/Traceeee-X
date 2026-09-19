"""
Application configuration management
"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings from environment variables"""

    # Application
    APP_NAME: str = "TRACE-X"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://tracex:tracex@localhost:5432/tracex"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Security
    SECRET_KEY: str = "CHANGE_THIS_IN_PRODUCTION_USE_LONG_RANDOM_STRING"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALGORITHM: str = "HS256"

    # AI Provider Configuration
    AI_PROVIDER: str = "openai"  # openai, anthropic, or demo
    AI_API_KEY: Optional[str] = None
    AI_MODEL: str = "gpt-4"  # gpt-4, claude-3-opus-20240229, etc.
    AI_MAX_TOKENS: int = 2000
    AI_TEMPERATURE: float = 0.3

    # Threat Intelligence Providers
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    IP_GEOLOCATION_API_KEY: Optional[str] = None

    # Intelligence Provider Mode
    USE_DEMO_INTELLIGENCE: bool = True  # Fallback to demo data when APIs unavailable

    # File Upload
    MAX_UPLOAD_SIZE_MB: int = 25
    ALLOWED_UPLOAD_EXTENSIONS: list[str] = [".eml", ".msg", ".txt"]

    # Email Analysis
    MAX_URLS_PER_EMAIL: int = 100
    MAX_ATTACHMENTS_PER_EMAIL: int = 20
    SUSPICIOUS_TLDS: list[str] = [".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".review"]
    SUSPICIOUS_EXTENSIONS: list[str] = [
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
        ".js", ".vbs", ".ps1", ".jar", ".app",
        ".docm", ".xlsm", ".pptm"
    ]

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60

    # Google Workspace & Gmail Ingestion
    GOOGLE_APPLICATION_CREDENTIALS: Optional[str] = None
    GOOGLE_SERVICE_ACCOUNT_INFO: Optional[str] = None  # JSON string representation of service account key
    GOOGLE_PUBSUB_TOPIC: Optional[str] = "projects/tracex-demo/topics/gmail-inbox-watch"  # Format: projects/{project_id}/topics/{topic_name}
    GOOGLE_PUBSUB_SUBSCRIPTION: Optional[str] = None
    GOOGLE_PUBSUB_VERIFICATION_TOKEN: Optional[str] = None  # Optional secret token to authenticate incoming push webhook
    GOOGLE_WORKSPACE_ADMIN_EMAIL: Optional[str] = None
    GMAIL_WATCH_USERS: list[str] = []  # List of mailbox email addresses to watch
    GMAIL_WATCH_RENEWAL_INTERVAL_HOURS: int = 24  # Watch expires after 7 days; renew every 24h
    GMAIL_WATCH_LABEL_IDS: list[str] = ["INBOX"]

    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173"
    ]

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
