"""
Case management models
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from app.database import Base


class CaseStatus(str, enum.Enum):
    """Case status enumeration"""
    OPEN = "open"
    UNDER_INVESTIGATION = "under_investigation"
    CONTAINED = "contained"
    CLOSED = "closed"


class CaseSeverity(str, enum.Enum):
    """Case severity enumeration"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Case(Base):
    """Investigation case model"""
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, unique=True, index=True, nullable=False)  # Human-readable ID
    title = Column(String, nullable=False)
    description = Column(Text)

    status = Column(Enum(CaseStatus), default=CaseStatus.OPEN, nullable=False, index=True)
    severity = Column(Enum(CaseSeverity), default=CaseSeverity.MEDIUM, nullable=False, index=True)

    # Assigned analyst
    analyst_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    analyst = relationship("User", backref="cases")

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    emails = relationship("Email", back_populates="case", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="case", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Case(case_id={self.case_id}, status={self.status}, severity={self.severity})>"
