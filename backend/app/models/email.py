"""
Email analysis models
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON, ForeignKey, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class Email(Base):
    """Email model for storing parsed email data"""
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(String, unique=True, index=True, nullable=False)  # UUID
    message_id = Column(String, index=True)  # Email Message-ID header

    # Basic email fields
    subject = Column(Text)
    from_address = Column(String, index=True)
    to_addresses = Column(JSON)  # List of recipient addresses
    cc_addresses = Column(JSON, nullable=True)
    reply_to = Column(String, nullable=True)
    return_path = Column(String, nullable=True)

    # Email content
    body_plain = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)

    # Email date
    date_sent = Column(DateTime(timezone=True), nullable=True)
    date_received = Column(DateTime(timezone=True), server_default=func.now())

    # Analysis results
    is_suspicious = Column(Boolean, default=False, index=True)
    is_malicious = Column(Boolean, default=False, index=True)
    threat_type = Column(String, nullable=True, index=True)  # phishing, spoofing, malware, etc.
    risk_score = Column(Float, default=0.0, index=True)

    # Authentication results
    spf_result = Column(String, nullable=True)  # PASS, FAIL, NEUTRAL, NONE
    dkim_result = Column(String, nullable=True)
    dmarc_result = Column(String, nullable=True)

    # AI analysis
    ai_classification = Column(String, nullable=True)
    ai_confidence = Column(Float, nullable=True)
    ai_reasoning = Column(Text, nullable=True)
    ai_indicators = Column(JSON, nullable=True)

    # Raw email
    raw_email = Column(Text, nullable=True)

    # Case association
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True, index=True)
    case = relationship("Case", back_populates="emails")

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    analyzed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    headers = relationship("EmailHeader", back_populates="email", cascade="all, delete-orphan")
    urls = relationship("URLAnalysis", back_populates="email", cascade="all, delete-orphan")
    attachments = relationship("AttachmentAnalysis", back_populates="email", cascade="all, delete-orphan")
    ip_intelligence = relationship("IPIntelligence", back_populates="email", cascade="all, delete-orphan")
    domain_intelligence = relationship("DomainIntelligence", back_populates="email", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Email(email_id={self.email_id}, from={self.from_address}, risk_score={self.risk_score})>"


class EmailHeader(Base):
    """Email header information"""
    __tablename__ = "email_headers"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)

    # Header details
    name = Column(String, nullable=False, index=True)
    value = Column(Text, nullable=False)

    # For Received headers - track email path
    hop_number = Column(Integer, nullable=True)  # Order in the chain
    from_ip = Column(String, nullable=True, index=True)
    from_hostname = Column(String, nullable=True)
    by_hostname = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=True)

    email = relationship("Email", back_populates="headers")

    def __repr__(self):
        return f"<EmailHeader(name={self.name}, value={self.value[:50]})>"
