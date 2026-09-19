"""
Evidence and forensic ledger models
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey, Enum, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from app.database import Base


class EvidenceType(str, enum.Enum):
    """Evidence type enumeration"""
    EMAIL_HEADER = "email_header"
    AUTHENTICATION = "authentication"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    ATTACHMENT = "attachment"
    THREAT_INTELLIGENCE = "threat_intelligence"
    AI_ANALYSIS = "ai_analysis"
    SYSTEM_LOG = "system_log"


class Evidence(Base):
    """Forensic evidence model with hash-chain integrity"""
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String, unique=True, index=True, nullable=False)  # UUID

    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=True, index=True)

    # Evidence details
    evidence_type = Column(Enum(EvidenceType), nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text)

    # Extracted data
    extracted_value = Column(Text, nullable=True)
    evidence_metadata = Column("metadata", JSON, nullable=True)

    # Source tracking
    source = Column(String, nullable=True)  # Where evidence came from
    collection_method = Column(String, nullable=True)  # How it was collected

    # Hash chain for integrity
    evidence_hash = Column(String, nullable=False)  # SHA-256 of evidence content
    previous_hash = Column(String, nullable=True)  # Hash of previous evidence in chain
    chain_index = Column(Integer, nullable=False)  # Position in chain

    # Integrity verification
    integrity_verified = Column(Boolean, default=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)

    # Timestamps
    collected_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    case = relationship("Case", back_populates="evidence")

    def __repr__(self):
        return f"<Evidence(evidence_id={self.evidence_id}, type={self.evidence_type}, chain_index={self.chain_index})>"
