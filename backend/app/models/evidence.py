"""
models/evidence.py
------------------
SQLAlchemy ORM model for Evidence Vault events.

Sprint 1 — Evidence Vault & Secure Log Ingestion.
Preserves raw security logs as immutable, tamper-evident evidence.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import Column, DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.types import JSON

from app.database import Base


class EvidenceEvent(Base):
    """
    Evidence Vault event record.

    Stores the unaltered raw security log, its cryptographic SHA-256 hash,
    ingestion timestamp, source identifiers, and verification status.
    """

    __tablename__ = "evidence_events"
    __table_args__ = (
        Index("ix_evidence_events_ingested_at", "ingested_at"),
        Index("ix_evidence_events_source_name", "source_name"),
        Index("ix_evidence_events_source_type", "source_type"),
        {"schema": "sentinel"},
    )

    event_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
        comment="Unique cryptographic event identifier (UUIDv4)",
    )

    source_name = Column(
        String(255),
        nullable=False,
        comment="Name of reporting system or device (e.g., 'Cisco ASA Firewall')",
    )

    source_type = Column(
        String(100),
        nullable=False,
        comment="Category of source log (e.g., 'firewall', 'authentication', 'endpoint')",
    )

    raw_event = Column(
        Text,
        nullable=False,
        comment="Exact original raw log event string preserved before any parsing/normalization",
    )

    raw_event_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 hexadecimal digest computed over exact UTF-8 encoded raw_event",
    )

    ingested_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC timestamp when evidence was ingested and sealed into vault",
    )

    metadata_ = Column(
        "metadata",
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Arbitrary contextual metadata (environment, collector ID, tags, etc.)",
    )

    integrity_status = Column(
        String(50),
        nullable=False,
        default="STORED",
        comment="Current cryptographic integrity state: STORED, INTEGRITY_VERIFIED, or TAMPER_DETECTED",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence record to a dictionary."""
        return {
            "event_id": str(self.event_id),
            "source_name": self.source_name,
            "source_type": self.source_type,
            "raw_event": self.raw_event,
            "raw_event_hash": self.raw_event_hash,
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
            "metadata": self.metadata_ or {},
            "integrity_status": self.integrity_status,
        }
