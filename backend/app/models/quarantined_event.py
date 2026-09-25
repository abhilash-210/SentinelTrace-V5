"""
models/quarantined_event.py
---------------------------
SQLAlchemy ORM model for Quarantined Security Events (DLQ).

Used to store raw logs that failed parsing or schema validation,
along with the failure reason and an API for future replay.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import Column, DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

from app.database import Base


class QuarantinedEvent(Base):
    """
    Quarantined security event model.

    Stores malformed or unparseable raw logs to prevent data loss.
    Provides fields to track the failure reason and resolution status.
    """

    __tablename__ = "quarantined_events"
    __table_args__ = (
        Index("ix_quarantined_events_event_id", "quarantine_id", unique=True),
        Index("ix_quarantined_events_quarantined_at", "quarantined_at"),
        Index("ix_quarantined_events_source_name", "source_name"),
        Index("ix_quarantined_events_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    quarantine_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"qrn_{uuid.uuid4().hex[:16]}",
        comment="Unique quarantine identifier (e.g., 'qrn_7f8a9b...')",
    )

    source_name = Column(
        String(255),
        nullable=False,
        comment="Source system or reporting device name",
    )

    source_type = Column(
        String(100),
        nullable=False,
        comment="Category of event source (e.g., 'firewall', 'application', 'system')",
    )

    original_event_id = Column(
        String(64),
        nullable=True,
        comment="Link back to the original IngestedEvent ID",
    )

    raw_content = Column(
        Text,
        nullable=False,
        comment="Exact unaltered raw event payload that failed processing",
    )

    failure_reason = Column(
        Text,
        nullable=False,
        comment="Detailed reason why this event failed validation or parsing",
    )

    quarantined_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC timestamp when the event was quarantined",
    )

    status = Column(
        String(50),
        nullable=False,
        default="QUARANTINED",
        comment="Status: 'QUARANTINED', 'REPLAYED', 'DISCARDED'",
    )

    metadata_ = Column(
        "metadata",
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Contextual metadata (collector tags, environment, origin)",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert ORM instance to a dictionary representation."""
        return {
            "id": self.id,
            "quarantine_id": self.quarantine_id,
            "source_name": self.source_name,
            "source_type": self.source_type,
            "original_event_id": self.original_event_id,
            "raw_content": self.raw_content,
            "failure_reason": self.failure_reason,
            "quarantined_at": self.quarantined_at.isoformat() if self.quarantined_at else None,
            "status": self.status,
            "metadata": self.metadata_ or {},
        }
