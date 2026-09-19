"""
Pydantic schemas for data validation and API models
"""
from pydantic import BaseModel, EmailStr, Field, ConfigDict, AliasChoices
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ==========================================
# Common / Enums
# ==========================================

class UserRoleEnum(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class CaseStatusEnum(str, Enum):
    OPEN = "open"
    UNDER_INVESTIGATION = "under_investigation"
    CONTAINED = "contained"
    CLOSED = "closed"


class CaseSeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertSeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceTypeEnum(str, Enum):
    EMAIL_HEADER = "email_header"
    AUTHENTICATION = "authentication"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    ATTACHMENT = "attachment"
    THREAT_INTELLIGENCE = "threat_intelligence"
    AI_ANALYSIS = "ai_analysis"
    SYSTEM_LOG = "system_log"


class AuthStatusEnum(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


# ==========================================
# User Schemas
# ==========================================

class UserBase(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    role: UserRoleEnum = UserRoleEnum.ANALYST
    is_active: bool = True


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[UserRoleEnum] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None


class UserResponse(UserBase):
    id: int
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenPayload(BaseModel):
    sub: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[int] = None


# ==========================================
# Authentication & Header Schemas
# ==========================================

class AuthResult(BaseModel):
    status: AuthStatusEnum
    details: Optional[str] = None
    raw_header: Optional[str] = None
    explanation: str


class EmailAuthenticationAnalysis(BaseModel):
    spf: AuthResult
    dkim: AuthResult
    dmarc: AuthResult
    arc: Optional[AuthResult] = None
    summary: str


class EmailHop(BaseModel):
    hop_number: int
    from_ip: Optional[str] = None
    from_hostname: Optional[str] = None
    by_hostname: Optional[str] = None
    timestamp: Optional[datetime] = None
    delay_seconds: Optional[int] = None
    anomalies: List[str] = []


class HeaderAnalysisResult(BaseModel):
    originating_ip: Optional[str] = None
    received_chain: List[EmailHop] = []
    sender_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    message_id_valid: bool = True
    anomalies: List[str] = []
    timezone_inconsistencies: List[str] = []


# ==========================================
# URL & Attachment Schemas
# ==========================================

class URLItem(BaseModel):
    url: str
    domain: Optional[str] = None
    protocol: Optional[str] = None
    is_suspicious: bool = False
    is_malicious: bool = False
    is_shortened: bool = False
    is_ip_based: bool = False
    has_suspicious_tld: bool = False
    uses_https: bool = False
    reputation_score: Optional[float] = None
    threat_types: List[str] = []
    indicators: List[str] = []


class AttachmentItem(BaseModel):
    filename: str
    file_extension: Optional[str] = None
    mime_type: Optional[str] = None
    file_size: Optional[int] = None
    sha256_hash: Optional[str] = None
    md5_hash: Optional[str] = None
    is_suspicious: bool = False
    is_malicious: bool = False
    is_executable: bool = False
    has_macros: bool = False
    reputation_score: Optional[float] = None
    threat_types: List[str] = []
    indicators: List[str] = []


# ==========================================
# Threat Intelligence Schemas
# ==========================================

class IPIntelligenceData(BaseModel):
    ip_address: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    is_hosting: Optional[bool] = None
    is_proxy: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_tor: Optional[bool] = None
    reputation_score: Optional[float] = None
    is_malicious: bool = False
    abuse_confidence_score: Optional[float] = None
    total_reports: Optional[int] = None
    provider: str = "local"
    context_note: str = "Geolocation is contextual intelligence and does not establish physical attribution."
    is_demo: bool = False


class DomainIntelligenceData(BaseModel):
    domain: str
    tld: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    is_malicious: bool = False
    is_suspicious: bool = False
    is_lookalike: bool = False
    lookalike_target: Optional[str] = None
    has_suspicious_tld: bool = False
    reputation_score: Optional[float] = None
    threat_types: List[str] = []
    provider: str = "local"
    is_demo: bool = False


# ==========================================
# Risk Scoring Schemas
# ==========================================

class RiskFactor(BaseModel):
    category: str
    points: float
    description: str
    evidence_ref: Optional[str] = None


class RiskScoreBreakdown(BaseModel):
    score: float = Field(..., ge=0.0, le=100.0)
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    factors: List[RiskFactor] = []
    explanation: str
    confidence: float = 1.0


# ==========================================
# AI Analysis Schemas
# ==========================================

class AIAnalysisResult(BaseModel):
    classification: str  # clean, spam, phishing, spear_phishing, bec, malware, spoofing
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    indicators: List[str] = []
    reasoning: str
    recommended_actions: List[str] = []
    evidence_citations: List[str] = []
    is_fallback: bool = False


# ==========================================
# Email Ingestion & Analysis Request/Response
# ==========================================

class RawEmailInput(BaseModel):
    raw_content: str
    source: Optional[str] = "manual_paste"


class EmailAnalysisResponse(BaseModel):
    email_id: str
    message_id: Optional[str] = None
    subject: Optional[str] = None
    from_address: Optional[str] = None
    to_addresses: List[str] = []
    cc_addresses: Optional[List[str]] = []
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    date_sent: Optional[datetime] = None
    date_received: Optional[datetime] = None

    # Analysis Verdicts
    is_suspicious: bool
    is_malicious: bool
    threat_type: Optional[str] = None
    risk_score: float
    severity: str

    # Deep Analysis Data
    authentication: EmailAuthenticationAnalysis
    header_analysis: HeaderAnalysisResult
    risk_breakdown: RiskScoreBreakdown
    ai_analysis: Optional[AIAnalysisResult] = None
    ip_intelligence: List[IPIntelligenceData] = []
    domain_intelligence: List[DomainIntelligenceData] = []
    urls: List[URLItem] = []
    attachments: List[AttachmentItem] = []

    # System IDs
    case_id: Optional[str] = None
    alert_id: Optional[str] = None
    analyzed_at: datetime
    is_demo: bool = False

    model_config = ConfigDict(from_attributes=True)


class EmailListItem(BaseModel):
    id: int
    email_id: str
    subject: Optional[str] = None
    from_address: Optional[str] = None
    to_addresses: Optional[List[str]] = None
    risk_score: float
    threat_type: Optional[str] = None
    is_malicious: bool
    is_suspicious: bool
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Evidence & Forensic Ledger Schemas
# ==========================================

class EvidenceCreate(BaseModel):
    case_id: int
    email_id: Optional[int] = None
    evidence_type: EvidenceTypeEnum
    title: str
    description: Optional[str] = None
    extracted_value: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    source: Optional[str] = None
    collection_method: Optional[str] = None


class EvidenceResponse(BaseModel):
    id: int
    evidence_id: str
    case_id: int
    email_id: Optional[int] = None
    evidence_type: EvidenceTypeEnum
    title: str
    description: Optional[str] = None
    extracted_value: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = Field(default=None, validation_alias=AliasChoices("metadata", "evidence_metadata"))
    source: Optional[str] = None
    evidence_hash: str
    previous_hash: Optional[str] = None
    chain_index: int
    integrity_verified: bool
    verified_at: Optional[datetime] = None
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LedgerVerificationResult(BaseModel):
    case_id: str
    total_records: int
    is_valid: bool
    compromised_index: Optional[int] = None
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ==========================================
# Case Schemas
# ==========================================

class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: CaseSeverityEnum = CaseSeverityEnum.MEDIUM
    analyst_id: Optional[int] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[CaseStatusEnum] = None
    severity: Optional[CaseSeverityEnum] = None
    analyst_id: Optional[int] = None


class CaseSummary(BaseModel):
    id: int
    case_id: str
    title: str
    description: Optional[str] = None
    status: CaseStatusEnum
    severity: CaseSeverityEnum
    analyst_name: Optional[str] = None
    emails_count: int = 0
    evidence_count: int = 0
    alerts_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseDetail(BaseModel):
    id: int
    case_id: str
    title: str
    description: Optional[str] = None
    status: CaseStatusEnum
    severity: CaseSeverityEnum
    analyst: Optional[UserResponse] = None
    emails: List[EmailListItem] = []
    evidence: List[EvidenceResponse] = []
    alerts: List[Any] = []
    timeline: List[Any] = []
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Alert Schemas
# ==========================================

class AlertResponse(BaseModel):
    id: int
    alert_id: str
    case_id: Optional[int] = None
    email_id: int
    severity: AlertSeverityEnum
    title: str
    description: Optional[str] = None
    threat_type: Optional[str] = None
    indicators: Optional[List[str]] = None
    recommended_actions: Optional[List[str]] = None
    is_acknowledged: bool = False
    is_resolved: bool = False
    triggered_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Timeline Schemas
# ==========================================

class TimelineEventResponse(BaseModel):
    id: int
    event_id: str
    case_id: int
    email_id: Optional[int] = None
    event_type: str
    title: str
    description: Optional[str] = None
    event_data: Optional[Dict[str, Any]] = None
    actor: Optional[str] = None
    event_timestamp: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Dashboard & Graph Schemas
# ==========================================

class DashboardStats(BaseModel):
    total_emails_analyzed: int
    threats_detected: int
    critical_alerts: int
    high_risk_emails: int
    suspicious_ips: int
    suspicious_domains: int
    malicious_urls: int
    cases_opened: int
    active_threats_percent: float


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # email, user, ip, domain, url, attachment, hash, case
    properties: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    type: str = "relates_to"


class InvestigationGraph(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


# ==========================================
# Report Schemas
# ==========================================

class InvestigationReport(BaseModel):
    case_id: str
    title: str
    executive_summary: str
    created_at: datetime
    analyst_name: Optional[str] = None
    severity: str
    status: str
    email_count: int
    primary_threat_type: Optional[str] = None
    highest_risk_score: float
    indicators_of_compromise: Dict[str, List[str]]
    evidence_summary: List[Dict[str, Any]]
    timeline_summary: List[Dict[str, Any]]
    recommended_actions: List[str]
    integrity_status: str


# ==========================================
# Google Workspace & PubSub Schemas
# ==========================================

class PubSubPushMessage(BaseModel):
    data: Optional[str] = None
    messageId: Optional[str] = None
    publishTime: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None


class PubSubPushEnvelope(BaseModel):
    message: Optional[PubSubPushMessage] = None
    subscription: Optional[str] = None


class MailboxWatchStatus(BaseModel):
    user_email: str
    topic_name: Optional[str] = None
    label_ids: List[str] = ["INBOX"]
    history_id: Optional[str] = None
    expiration_ms: Optional[int] = None
    expiration: Optional[str] = None
    status: str = "active"
    last_renewed: Optional[str] = None


# ==========================================
# SOC Analyst Copilot Chat Schemas
# ==========================================

class ChatMessage(BaseModel):
    role: str  # "user", "assistant", or "system"
    content: str


class ChatQueryRequest(BaseModel):
    messages: List[ChatMessage]
    threat_context: Optional[Dict[str, Any]] = None


class ChatQueryResponse(BaseModel):
    response: str
    role: str = "assistant"
    model: str
    threat_context_applied: bool = False
    suggested_actions: List[str] = []


