"""
models/detection_rule_trust.py
------------------------------
SQLAlchemy ORM models for Detection Rule Trust Evaluation and Detection Trust Alerts.

Sprint 6B — Detection Rule Trust Evaluation & Semantic Drift Binding.
Binds semantic drift detection to dependent detection rules, computing deterministic,
explainable trust scores and managing detection trust alert lifecycles.

Architectural Principles:
- Trust evaluation records represent immutable point-in-time security decisions.
- Historical evaluations MUST NOT be overwritten.
- Detection rule trust evaluations NEVER modify raw evidence, normalized events,
  semantic policies, interpretations, or drift alerts.
- Zero Trust Principle: UNKNOWN != SAFE (UNKNOWN must NEVER automatically become TRUSTED).
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


class DetectionRuleTrustEvaluation(Base):
    """
    Immutable point-in-time evaluation of a detection rule's trustworthiness
    under current or historical semantic interpretation and drift conditions.
    """

    __tablename__ = "detection_rule_trust_evaluations"
    __table_args__ = (
        Index("ix_trust_eval_evaluation_id", "evaluation_id", unique=True),
        Index("ix_trust_eval_rule_id", "rule_id"),
        Index("ix_trust_eval_normalized_event_id", "normalized_event_id"),
        Index("ix_trust_eval_interpretation_id", "interpretation_id"),
        Index("ix_trust_eval_drift_alert_id", "drift_alert_id"),
        Index("ix_trust_eval_canonical_field", "canonical_field"),
        Index("ix_trust_eval_trust_status", "trust_status"),
        Index("ix_trust_eval_risk_level", "risk_level"),
        Index("ix_trust_eval_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    evaluation_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"teval_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the trust evaluation record",
    )

    rule_id = Column(
        String(64),
        ForeignKey("sentinel.detection_rules.rule_id", ondelete="CASCADE"),
        nullable=False,
        comment="Foreign key to evaluated detection rule",
    )

    normalized_event_id = Column(
        String(64),
        nullable=True,
        comment="Link to sentinel.normalized_events.normalized_event_id (if evaluated in event context)",
    )

    interpretation_id = Column(
        String(64),
        nullable=True,
        comment="Link to sentinel.semantic_interpretations.interpretation_id (if evaluated in interpretation context)",
    )

    drift_alert_id = Column(
        String(64),
        nullable=True,
        comment="Link to sentinel.semantic_drift_alerts.alert_id (if triggered by drift alert)",
    )

    canonical_field = Column(
        String(128),
        nullable=False,
        comment="Primary canonical field triggering this evaluation or 'MULTIPLE_DEPENDENCIES'",
    )

    trust_status = Column(
        String(32),
        nullable=False,
        comment="Trust state: 'TRUSTED', 'DEGRADED', 'AT_RISK', 'INVALID', 'UNKNOWN'",
    )

    trust_score = Column(
        Float,
        nullable=False,
        comment="Deterministic trust score between 0.00 and 1.00",
    )

    risk_level = Column(
        String(32),
        nullable=False,
        comment="Associated risk classification: 'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    evaluation_reasons = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="Ordered list of step-by-step mathematical deductions and context notes",
    )

    explanation = Column(
        Text,
        nullable=False,
        comment="Comprehensive human-readable security explanation of the trust determination",
    )

    evaluation_version = Column(
        Integer,
        nullable=False,
        default=1,
        comment="Version of the evaluation engine used",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC creation timestamp",
    )

    # Relationships
    rule = relationship("DetectionRule", foreign_keys=[rule_id], lazy="joined")
    trust_alerts = relationship(
        "DetectionTrustAlert",
        back_populates="evaluation",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert trust evaluation record to dictionary."""
        return {
            "id": self.id,
            "evaluation_id": self.evaluation_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule.rule_name if self.rule else None,
            "rule_severity": self.rule.severity if self.rule else None,
            "vendor_name": self.rule.vendor_name if self.rule else None,
            "normalized_event_id": self.normalized_event_id,
            "interpretation_id": self.interpretation_id,
            "drift_alert_id": self.drift_alert_id,
            "canonical_field": self.canonical_field,
            "trust_status": self.trust_status,
            "trust_score": round(self.trust_score, 4) if self.trust_score is not None else 0.0,
            "risk_level": self.risk_level,
            "evaluation_reasons": self.evaluation_reasons or [],
            "explanation": self.explanation,
            "evaluation_version": self.evaluation_version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DetectionTrustAlert(Base):
    """
    Security alert generated when a detection rule's trust state degrades,
    invalidates, or poses an active risk due to semantic drift.
    """

    __tablename__ = "detection_trust_alerts"
    __table_args__ = (
        Index("ix_trust_alerts_alert_id", "alert_id", unique=True),
        Index("ix_trust_alerts_rule_id", "rule_id"),
        Index("ix_trust_alerts_eval_id", "evaluation_id"),
        Index("ix_trust_alerts_drift_alert_id", "drift_alert_id"),
        Index("ix_trust_alerts_severity", "severity"),
        Index("ix_trust_alerts_status", "status"),
        Index("ix_trust_alerts_alert_type", "alert_type"),
        Index("ix_trust_alerts_created_at", "created_at"),
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
        default=lambda: f"dtalert_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the detection trust alert",
    )

    rule_id = Column(
        String(64),
        ForeignKey("sentinel.detection_rules.rule_id", ondelete="CASCADE"),
        nullable=False,
        comment="Foreign key to affected detection rule",
    )

    evaluation_id = Column(
        String(64),
        ForeignKey("sentinel.detection_rule_trust_evaluations.evaluation_id", ondelete="CASCADE"),
        nullable=False,
        comment="Foreign key to triggering trust evaluation",
    )

    drift_alert_id = Column(
        String(64),
        nullable=True,
        comment="Link to triggering semantic drift alert (if applicable)",
    )

    alert_type = Column(
        String(64),
        nullable=False,
        comment="Alert category: 'RULE_TRUST_DEGRADED', 'RULE_AT_RISK', 'RULE_INVALIDATED', 'UNKNOWN_DEPENDENCY', 'CRITICAL_SEMANTIC_DEPENDENCY'",
    )

    severity = Column(
        String(32),
        nullable=False,
        comment="Severity rating: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    status = Column(
        String(32),
        nullable=False,
        default="OPEN",
        comment="Triage status: 'OPEN', 'ACKNOWLEDGED', 'RESOLVED'",
    )

    description = Column(
        Text,
        nullable=False,
        comment="Actionable description of the detection rule trust degradation",
    )

    affected_field = Column(
        String(128),
        nullable=False,
        comment="Canonical field whose semantic drift caused this alert",
    )

    trust_status = Column(
        String(32),
        nullable=False,
        comment="Trust state at alert creation: 'DEGRADED', 'AT_RISK', 'INVALID', 'UNKNOWN'",
    )

    trust_score = Column(
        Float,
        nullable=False,
        comment="Trust score at time of alert creation",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC creation timestamp",
    )

    resolved_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when alert was acknowledged or resolved",
    )

    # Relationships
    rule = relationship("DetectionRule", foreign_keys=[rule_id], lazy="joined")
    evaluation = relationship("DetectionRuleTrustEvaluation", back_populates="trust_alerts", foreign_keys=[evaluation_id])

    def to_dict(self) -> Dict[str, Any]:
        """Convert detection trust alert to dictionary."""
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule.rule_name if self.rule else None,
            "evaluation_id": self.evaluation_id,
            "drift_alert_id": self.drift_alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "status": self.status,
            "description": self.description,
            "affected_field": self.affected_field,
            "trust_status": self.trust_status,
            "trust_score": round(self.trust_score, 4) if self.trust_score is not None else 0.0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }
