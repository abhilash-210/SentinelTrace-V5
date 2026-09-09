"""
models/semantic_interpretation.py
---------------------------------
SQLAlchemy ORM models for Semantic Interpretation Records and Semantic Drift Alerts.

Sprint 3B — Semantic Interpretation Engine & Semantic Drift Detection.
Strictly separates structural parsing from vendor-scoped semantic interpretation,
ensuring derived semantic records are created without modifying normalized events or raw evidence.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON

from app.database import Base


class SemanticInterpretation(Base):
    """
    Derived semantic interpretation record.
    Represents vendor-scoped policy evaluation of a normalized event.
    """

    __tablename__ = "semantic_interpretations"
    __table_args__ = (
        Index("ix_semantic_interpretations_interpretation_id", "interpretation_id", unique=True),
        Index("ix_semantic_interpretations_normalized_event_id", "normalized_event_id"),
        Index("ix_semantic_interpretations_original_event_id", "original_event_id"),
        Index("ix_semantic_interpretations_policy_id", "policy_id"),
        Index("ix_semantic_interpretations_status", "interpretation_status"),
        Index("ix_semantic_interpretations_risk_level", "risk_level"),
        Index("ix_semantic_interpretations_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    interpretation_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"interp_{uuid.uuid4().hex[:16]}",
        comment="Unique identifier for the semantic interpretation record",
    )

    normalized_event_id = Column(
        String(64),
        nullable=False,
        comment="Link to sentinel.normalized_events.normalized_event_id",
    )

    original_event_id = Column(
        String(64),
        nullable=False,
        comment="Direct link back to raw evidence in sentinel.ingested_events.event_id",
    )

    policy_id = Column(
        String(64),
        nullable=True,
        comment="Matched vendor semantic policy ID (e.g. 'spol_cisco_asa_v1')",
    )

    policy_version = Column(
        Integer,
        nullable=True,
        comment="Version of the evaluated semantic policy",
    )

    vendor_name = Column(
        String(255),
        nullable=False,
        comment="Originating vendor context (e.g. 'Cisco ASA', 'Demo Vendor')",
    )

    source_profile_id = Column(
        String(64),
        nullable=False,
        comment="Source profile identifier for structural log interpretation",
    )

    source_field = Column(
        String(100),
        nullable=False,
        comment="Evaluated source field name (e.g. 'action')",
    )

    source_value = Column(
        String(255),
        nullable=False,
        comment="Raw value extracted from source (e.g. 'PERMIT')",
    )

    canonical_field = Column(
        String(100),
        nullable=False,
        comment="Target canonical field name (e.g. 'action.result')",
    )

    interpreted_value = Column(
        String(255),
        nullable=True,
        comment="Interpreted canonical value (e.g. 'ALLOWED', 'MONITORED')",
    )

    equivalence_classification = Column(
        String(32),
        nullable=True,
        comment="Equivalence level: 'EQUIVALENT', 'COMPATIBLE', 'AMBIGUOUS', 'INCOMPATIBLE'",
    )

    risk_level = Column(
        String(32),
        nullable=False,
        default="LOW",
        comment="Evaluated semantic risk level: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    interpretation_status = Column(
        String(32),
        nullable=False,
        default="INTERPRETED",
        comment="Status: 'INTERPRETED', 'UNMAPPED', 'AMBIGUOUS', 'CONFLICT', 'FAILED'",
    )

    confidence_score = Column(
        Float,
        nullable=False,
        default=1.0,
        comment="Deterministic semantic interpretation confidence score (0.0 to 1.0)",
    )

    confidence_reasons = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of explanatory factors and penalties applied to semantic confidence",
    )

    explanation = Column(
        Text,
        nullable=False,
        comment="Human-readable explanation of the semantic decision and rule derivation",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC creation timestamp",
    )

    # Relationship to drift alerts
    drift_alerts = relationship(
        "SemanticDriftAlert",
        back_populates="interpretation",
        cascade="all, delete-orphan",
        lazy="joined",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert interpretation record to dictionary."""
        return {
            "id": self.id,
            "interpretation_id": self.interpretation_id,
            "normalized_event_id": self.normalized_event_id,
            "original_event_id": self.original_event_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "vendor_name": self.vendor_name,
            "source_profile_id": self.source_profile_id,
            "source_field": self.source_field,
            "source_value": self.source_value,
            "canonical_field": self.canonical_field,
            "interpreted_value": self.interpreted_value,
            "equivalence_classification": self.equivalence_classification,
            "risk_level": self.risk_level,
            "interpretation_status": self.interpretation_status,
            "confidence_score": self.confidence_score,
            "confidence_reasons": self.confidence_reasons or [],
            "explanation": self.explanation,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "drift_alerts": [a.to_dict() for a in self.drift_alerts] if self.drift_alerts is not None else [],
        }


class SemanticDriftAlert(Base):
    """
    Defensive semantic drift and anomaly alert generated during policy evaluation.
    """

    __tablename__ = "semantic_drift_alerts"
    __table_args__ = (
        Index("ix_semantic_drift_alerts_alert_id", "alert_id", unique=True),
        Index("ix_semantic_drift_alerts_normalized_event_id", "normalized_event_id"),
        Index("ix_semantic_drift_alerts_interpretation_id", "interpretation_id"),
        Index("ix_semantic_drift_alerts_drift_type", "drift_type"),
        Index("ix_semantic_drift_alerts_severity", "severity"),
        Index("ix_semantic_drift_alerts_status", "status"),
        Index("ix_semantic_drift_alerts_detected_at", "detected_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    alert_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"drift_{uuid.uuid4().hex[:16]}",
        comment="Unique identifier for the drift alert",
    )

    normalized_event_id = Column(
        String(64),
        nullable=False,
        comment="Link to sentinel.normalized_events.normalized_event_id",
    )

    interpretation_id = Column(
        String(64),
        ForeignKey("sentinel.semantic_interpretations.interpretation_id", ondelete="CASCADE"),
        nullable=True,
        comment="Link to parent interpretation record",
    )

    policy_id = Column(
        String(64),
        nullable=True,
        comment="Associated semantic policy identifier",
    )

    drift_type = Column(
        String(50),
        nullable=False,
        comment="Category: 'UNMAPPED_VALUE', 'AMBIGUOUS_MAPPING', 'POLICY_CONFLICT', 'PROTECTED_FIELD_RISK', 'INCOMPATIBLE_MAPPING'",
    )

    severity = Column(
        String(32),
        nullable=False,
        default="MEDIUM",
        comment="Alert severity: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    status = Column(
        String(32),
        nullable=False,
        default="OPEN",
        comment="Alert state: 'OPEN', 'ACKNOWLEDGED', 'RESOLVED'",
    )

    description = Column(
        Text,
        nullable=False,
        comment="Detailed explanation of the semantic divergence or risk",
    )

    expected_value = Column(
        String(255),
        nullable=True,
        comment="Expected canonical value or schema requirement",
    )

    observed_value = Column(
        String(255),
        nullable=True,
        comment="Observed raw or mapped value",
    )

    detected_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC timestamp when drift was detected",
    )

    resolved_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when drift was resolved",
    )

    # Parent relationship
    interpretation = relationship("SemanticInterpretation", back_populates="drift_alerts")

    def to_dict(self) -> Dict[str, Any]:
        """Convert drift alert to dictionary representation."""
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "normalized_event_id": self.normalized_event_id,
            "interpretation_id": self.interpretation_id,
            "policy_id": self.policy_id,
            "drift_type": self.drift_type,
            "severity": self.severity,
            "status": self.status,
            "description": self.description,
            "expected_value": self.expected_value,
            "observed_value": self.observed_value,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }
