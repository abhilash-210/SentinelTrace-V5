"""
models/normalized_event.py
--------------------------
SQLAlchemy ORM model for OCSF-Aligned Normalized Security Events.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
Establishes canonical security schema while maintaining strict 100% traceability
to the original raw evidence stored in the Evidence Vault.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import Column, DateTime, Float, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

from app.database import Base


class NormalizedEvent(Base):
    """
    OCSF-aligned normalized security event model.

    Preserves full bidirectional traceability back to the raw event in PostgreSQL
    via `original_event_id`. Missing fields remain NULL without fabrication.
    """

    __tablename__ = "normalized_events"
    __table_args__ = (
        Index("ix_normalized_events_normalized_id", "normalized_event_id", unique=True),
        Index("ix_normalized_events_original_id", "original_event_id"),
        Index("ix_normalized_events_class_name", "class_name"),
        Index("ix_normalized_events_status", "normalization_status"),
        Index("ix_normalized_events_normalized_at", "normalized_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Surrogate primary key",
    )

    normalized_event_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"norm_{uuid.uuid4().hex[:16]}",
        comment="Unique normalized canonical event identifier",
    )

    original_event_id = Column(
        String(64),
        nullable=False,
        comment="Traceability reference to raw event in sentinel.ingested_events.event_id",
    )

    # ── OCSF-Aligned Canonical Classification ──────────────────────────────────
    class_uid = Column(
        Integer,
        nullable=False,
        default=0,
        comment="OCSF Class UID (e.g. 4001: Network, 3001: Auth, 1001: System)",
    )

    class_name = Column(
        String(100),
        nullable=False,
        comment="Canonical OCSF Class name ('Network Activity', 'Authentication', 'System Activity')",
    )

    activity_id = Column(
        Integer,
        nullable=False,
        default=0,
        comment="OCSF Activity ID",
    )

    activity_name = Column(
        String(100),
        nullable=False,
        comment="Canonical activity label (e.g. 'Traffic Allowed', 'Logon Failure', 'Process Launch')",
    )

    event_time = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Parsed security event occurrence timestamp (UTC)",
    )

    source_name = Column(
        String(255),
        nullable=False,
        comment="Reporting source system or device identifier",
    )

    source_type = Column(
        String(100),
        nullable=False,
        comment="Origin category ('firewall', 'authentication', 'system')",
    )

    # ── Canonical Security Fields ──────────────────────────────────────────────
    action = Column(
        String(50),
        nullable=True,
        comment="Normalized action taken: 'ALLOW', 'DENY', 'SUCCESS', 'FAILURE', etc.",
    )

    src_ip = Column(
        String(45),
        nullable=True,
        comment="Normalized source IPv4/IPv6 address",
    )

    src_port = Column(
        Integer,
        nullable=True,
        comment="Normalized source port (1-65535)",
    )

    dst_ip = Column(
        String(45),
        nullable=True,
        comment="Normalized destination IPv4/IPv6 address",
    )

    dst_port = Column(
        Integer,
        nullable=True,
        comment="Normalized destination port (1-65535)",
    )

    protocol = Column(
        String(30),
        nullable=True,
        comment="Normalized network protocol (e.g. 'TCP', 'UDP', 'ICMP')",
    )

    severity = Column(
        String(30),
        nullable=True,
        comment="Extracted or mapped severity (e.g. 'Informational', 'Warning', 'Critical')",
    )

    user_name = Column(
        String(255),
        nullable=True,
        comment="Extracted actor / target username",
    )

    hostname = Column(
        String(255),
        nullable=True,
        comment="Extracted endpoint or server hostname",
    )

    process_name = Column(
        String(255),
        nullable=True,
        comment="Extracted process / executable name",
    )

    process_id = Column(
        Integer,
        nullable=True,
        comment="Extracted operating system process ID (PID)",
    )

    raw_data = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Dictionary of all format-specifically extracted raw key-value pairs",
    )

    unmapped_data = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Dictionary of all vendor-specific raw fields that could not be mapped to OCSF",
    )

    # ── Parser & Confidence Metadata ───────────────────────────────────────────
    parser_name = Column(
        String(100),
        nullable=False,
        comment="Name of parser module used ('SyslogParser', 'JSONParser', 'CSVParser')",
    )

    parser_version = Column(
        String(32),
        nullable=False,
        default="1.0.0",
        comment="Parser release version for deterministic reproducibility",
    )

    source_profile_id = Column(
        String(64),
        nullable=True,
        comment="Source profile applied during normalization",
    )

    normalization_status = Column(
        String(50),
        nullable=False,
        default="NORMALIZED",
        comment="Outcome status: 'NORMALIZED', 'PARTIAL', 'FAILED'",
    )

    normalization_confidence = Column(
        Float,
        nullable=False,
        default=1.0,
        comment="Deterministic heuristic confidence score (0.0 to 1.0)",
    )

    confidence_reasons = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of explanatory factors influencing the confidence score",
    )

    normalized_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC timestamp when normalization was computed and committed",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert normalized event to a dictionary representation."""
        return {
            "id": self.id,
            "normalized_event_id": self.normalized_event_id,
            "original_event_id": self.original_event_id,
            "class_uid": self.class_uid,
            "class_name": self.class_name,
            "activity_id": self.activity_id,
            "activity_name": self.activity_name,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "source_name": self.source_name,
            "source_type": self.source_type,
            "action": self.action,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "severity": self.severity,
            "user_name": self.user_name,
            "hostname": self.hostname,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "raw_data": self.raw_data or {},
            "unmapped_data": self.unmapped_data or {},
            "parser_name": self.parser_name,
            "parser_version": self.parser_version,
            "source_profile_id": self.source_profile_id,
            "normalization_status": self.normalization_status,
            "normalization_confidence": self.normalization_confidence,
            "confidence_reasons": self.confidence_reasons or [],
            "normalized_at": self.normalized_at.isoformat() if self.normalized_at else None,
        }
