"""
models/replay_operation.py
--------------------------
SQLAlchemy ORM model for Quarantine Replay Operations.

Used to track the history and outcome of event replays from the DLQ.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text

from app.database import Base


class ReplayOperation(Base):
    """
    Replay Operation model.

    Stores the outcome of an attempt to replay a quarantined event.
    """

    __tablename__ = "replay_operations"
    __table_args__ = (
        Index("ix_replay_operations_replay_id", "replay_id", unique=True),
        Index("ix_replay_operations_quarantine_id", "quarantine_id"),
        Index("ix_replay_operations_original_event_id", "original_event_id"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    replay_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"rpl_{uuid.uuid4().hex[:16]}",
        comment="Unique replay identifier (e.g., 'rpl_7f8a9b...')",
    )

    quarantine_id = Column(
        String(64),
        nullable=False,
        comment="Link back to the QuarantinedEvent",
    )

    original_event_id = Column(
        String(64),
        nullable=False,
        comment="Link back to the IngestedEvent",
    )

    replayed_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC timestamp when the replay occurred",
    )

    previous_status = Column(
        String(50),
        nullable=False,
        comment="The status of the quarantined event before this replay",
    )

    result = Column(
        String(50),
        nullable=False,
        comment="Result: 'SUCCESS', 'FAILED'",
    )

    resulting_normalized_event_id = Column(
        String(64),
        nullable=True,
        comment="The ID of the new normalized event if successful",
    )

    failure_reason = Column(
        Text,
        nullable=True,
        comment="Detailed reason why this replay failed",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert ORM instance to a dictionary representation."""
        return {
            "id": self.id,
            "replay_id": self.replay_id,
            "quarantine_id": self.quarantine_id,
            "original_event_id": self.original_event_id,
            "replayed_at": self.replayed_at.isoformat() if self.replayed_at else None,
            "previous_status": self.previous_status,
            "result": self.result,
            "resulting_normalized_event_id": self.resulting_normalized_event_id,
            "failure_reason": self.failure_reason,
        }
