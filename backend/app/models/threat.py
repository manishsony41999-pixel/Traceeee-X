"""
Threat intelligence and analysis models
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON, ForeignKey, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class ThreatIntelligence(Base):
    """Base threat intelligence model"""
    __tablename__ = "threat_intelligence"

    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String, nullable=False, index=True)  # ip, domain, url, hash
    indicator_value = Column(String, nullable=False, index=True)

    # Reputation data
    reputation_score = Column(Float, nullable=True)
    is_malicious = Column(Boolean, default=False, index=True)
    threat_types = Column(JSON, nullable=True)  # List of threat categories

    # Source information
    source_provider = Column(String, nullable=True)  # virustotal, abuseipdb, etc.
    source_data = Column(JSON, nullable=True)  # Raw response from provider

    # Timestamps
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    checked_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<ThreatIntelligence(type={self.indicator_type}, value={self.indicator_value}, malicious={self.is_malicious})>"


class IPIntelligence(Base):
    """IP address intelligence"""
    __tablename__ = "ip_intelligence"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)

    ip_address = Column(String, nullable=False, index=True)

    # Geolocation
    country = Column(String, nullable=True)
    country_code = Column(String, nullable=True)
    region = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)

    # Network information
    isp = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    organization = Column(String, nullable=True)
    is_hosting = Column(Boolean, nullable=True)
    is_proxy = Column(Boolean, nullable=True)
    is_vpn = Column(Boolean, nullable=True)
    is_tor = Column(Boolean, nullable=True)

    # Reputation
    reputation_score = Column(Float, nullable=True)
    is_malicious = Column(Boolean, default=False)
    abuse_confidence_score = Column(Float, nullable=True)
    total_reports = Column(Integer, nullable=True)

    # Provider information
    provider = Column(String, nullable=True)
    raw_data = Column(JSON, nullable=True)

    # Contextual note
    context_note = Column(Text, nullable=True)  # Important: geolocation context

    checked_at = Column(DateTime(timezone=True), server_default=func.now())

    email = relationship("Email", back_populates="ip_intelligence")

    def __repr__(self):
        return f"<IPIntelligence(ip={self.ip_address}, country={self.country}, malicious={self.is_malicious})>"


class DomainIntelligence(Base):
    """Domain reputation and intelligence"""
    __tablename__ = "domain_intelligence"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)

    domain = Column(String, nullable=False, index=True)

    # Domain information
    tld = Column(String, nullable=True)
    registrar = Column(String, nullable=True)
    creation_date = Column(DateTime(timezone=True), nullable=True)
    expiration_date = Column(DateTime(timezone=True), nullable=True)
    domain_age_days = Column(Integer, nullable=True)

    # Reputation
    reputation_score = Column(Float, nullable=True)
    is_malicious = Column(Boolean, default=False)
    is_suspicious = Column(Boolean, default=False)
    threat_types = Column(JSON, nullable=True)

    # Characteristics
    is_lookalike = Column(Boolean, default=False)
    lookalike_target = Column(String, nullable=True)
    has_suspicious_tld = Column(Boolean, default=False)

    # Provider information
    provider = Column(String, nullable=True)
    raw_data = Column(JSON, nullable=True)

    checked_at = Column(DateTime(timezone=True), server_default=func.now())

    email = relationship("Email", back_populates="domain_intelligence")

    def __repr__(self):
        return f"<DomainIntelligence(domain={self.domain}, malicious={self.is_malicious})>"


class URLAnalysis(Base):
    """URL analysis and reputation"""
    __tablename__ = "url_analysis"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)

    url = Column(Text, nullable=False)
    url_hash = Column(String, index=True)  # SHA-256 hash for deduplication

    # URL components
    protocol = Column(String, nullable=True)
    domain = Column(String, nullable=True, index=True)
    path = Column(Text, nullable=True)

    # Analysis
    is_suspicious = Column(Boolean, default=False)
    is_malicious = Column(Boolean, default=False)
    reputation_score = Column(Float, nullable=True)
    threat_types = Column(JSON, nullable=True)

    # Characteristics
    is_shortened = Column(Boolean, default=False)
    is_ip_based = Column(Boolean, default=False)
    has_suspicious_tld = Column(Boolean, default=False)
    uses_https = Column(Boolean, default=False)
    redirect_chain = Column(JSON, nullable=True)

    # Provider information
    provider = Column(String, nullable=True)
    raw_data = Column(JSON, nullable=True)

    checked_at = Column(DateTime(timezone=True), server_default=func.now())

    email = relationship("Email", back_populates="urls")

    def __repr__(self):
        return f"<URLAnalysis(domain={self.domain}, malicious={self.is_malicious})>"


class AttachmentAnalysis(Base):
    """Email attachment analysis"""
    __tablename__ = "attachment_analysis"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)

    # File information
    filename = Column(String, nullable=False)
    file_extension = Column(String, nullable=True, index=True)
    mime_type = Column(String, nullable=True)
    file_size = Column(Integer, nullable=True)

    # Hashes
    md5_hash = Column(String, nullable=True, index=True)
    sha256_hash = Column(String, nullable=True, index=True)

    # Analysis
    is_suspicious = Column(Boolean, default=False)
    is_malicious = Column(Boolean, default=False)
    reputation_score = Column(Float, nullable=True)
    threat_types = Column(JSON, nullable=True)

    # Characteristics
    is_executable = Column(Boolean, default=False)
    has_macros = Column(Boolean, default=False)
    is_encrypted = Column(Boolean, default=False)
    is_password_protected = Column(Boolean, default=False)

    # Provider information
    provider = Column(String, nullable=True)
    raw_data = Column(JSON, nullable=True)

    checked_at = Column(DateTime(timezone=True), server_default=func.now())

    email = relationship("Email", back_populates="attachments")

    def __repr__(self):
        return f"<AttachmentAnalysis(filename={self.filename}, malicious={self.is_malicious})>"
