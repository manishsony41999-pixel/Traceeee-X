"""
Timeline event models for investigation chronology
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class TimelineEvent(Base):
    """Timeline event for investigation"""
    __tablename__ = "timeline_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, unique=True, index=True, nullable=False)  # UUID

    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=True, index=True)

    # Event details
    event_type = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)

    # Event data
    event_data = Column(JSON, nullable=True)

    # Actor information
    actor = Column(String, nullable=True)  # System, Analyst, AI, etc.

    # Timestamps
    event_timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    case = relationship("Case", back_populates="timeline_events")

    def __repr__(self):
        return f"<TimelineEvent(event_id={self.event_id}, type={self.event_type}, timestamp={self.event_timestamp})>"
