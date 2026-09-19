"""
Alert models
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from app.database import Base


class AlertSeverity(str, enum.Enum):
    """Alert severity enumeration"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Alert(Base):
    """Security alert model"""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True, nullable=False)  # UUID

    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)

    # Alert details
    severity = Column(Enum(AlertSeverity), nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    threat_type = Column(String, nullable=True, index=True)

    # Indicators
    indicators = Column(JSON, nullable=True)  # List of indicators that triggered alert

    # Recommended actions
    recommended_actions = Column(JSON, nullable=True)

    # Status
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)

    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Timestamps
    triggered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    case = relationship("Case", back_populates="alerts")

    def __repr__(self):
        return f"<Alert(alert_id={self.alert_id}, severity={self.severity}, threat_type={self.threat_type})>"
