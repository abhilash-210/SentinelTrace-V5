"""
models/event.py
---------------
SQLAlchemy ORM model for Ingested Security Events and Evidence Preservation.

Sprint 1 — Raw Event Preservation & Traceable Ingestion.
Ensures data integrity, traceability, and auditability.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import Column, DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

from app.database import Base


class IngestedEvent(Base):
    """
    Ingested security event model.

    Preserves the original raw log/event string exactly as received, computes
    a SHA-256 integrity fingerprint, and assigns a unique traceable identifier.
    """

    __tablename__ = "ingested_events"
    __table_args__ = (
        Index("ix_ingested_events_event_id", "event_id", unique=True),
        Index("ix_ingested_events_ingested_at", "ingested_at"),
        Index("ix_ingested_events_source_name", "source_name"),
        Index("ix_ingested_events_source_type", "source_type"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    event_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"evt_{uuid.uuid4().hex[:16]}",
        comment="Unique traceable event identifier (e.g., 'evt_7f8a9b...')",
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

    file_format = Column(
        String(50),
        nullable=False,
        default="text",
        comment="Payload format: 'text', 'json', 'csv', 'syslog'",
    )

    raw_content = Column(
        Text,
        nullable=False,
        comment="Exact unaltered raw event payload preserved prior to any parsing",
    )

    raw_content_hash = Column(
        String(64),
        nullable=False,
        comment="Cryptographic SHA-256 fingerprint computed over exact UTF-8 raw_content",
    )

    content_size = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Size of raw_content in bytes",
    )

    ingested_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC timestamp of ingestion and preservation",
    )

    processing_status = Column(
        String(50),
        nullable=False,
        default="PRESERVED",
        comment="Integrity & processing state: 'PRESERVED', 'VERIFIED', 'MISMATCH'",
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
            "event_id": self.event_id,
            "source_name": self.source_name,
            "source_type": self.source_type,
            "file_format": self.file_format,
            "raw_content": self.raw_content,
            "raw_content_hash": self.raw_content_hash,
            "hash_prefix": self.raw_content_hash[:12] if self.raw_content_hash else "",
            "content_size": self.content_size,
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
            "processing_status": self.processing_status,
            "metadata": self.metadata_ or {},
        }
