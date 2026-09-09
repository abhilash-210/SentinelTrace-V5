"""
models/remediation.py
---------------------
SQLAlchemy ORM models for Remediation Candidates and Remediation Actions.

Sprint 7B — Security Posture Risk Correlation, Prioritized Remediation & Executive Risk Intelligence.
Manages deterministic, evidence-backed remediation candidates, priority scoring,
hypothetical impact simulations, and auditable lifecycle transitions.
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


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RemediationCandidate(Base):
    """
    Proposed corrective remediation action generated deterministically from security posture risk correlations.
    """

    __tablename__ = "remediation_candidates"
    __table_args__ = (
        Index("ix_remediation_remediation_id", "remediation_id", unique=True),
        Index("ix_remediation_type", "remediation_type"),
        Index("ix_remediation_priority_score", "priority_score"),
        Index("ix_remediation_priority_class", "priority_classification"),
        Index("ix_remediation_severity", "severity"),
        Index("ix_remediation_status", "status"),
        Index("ix_remediation_corr_id", "related_correlation_id"),
        Index("ix_remediation_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    remediation_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"rem_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for remediation candidate (e.g. rem_...)",
    )

    title = Column(
        String(255),
        nullable=False,
        comment="Action-oriented title for the remediation recommendation",
    )

    description = Column(
        Text,
        nullable=False,
        comment="Detailed technical description and instructions for remediation",
    )

    remediation_type = Column(
        String(64),
        nullable=False,
        comment="Category: 'SEMANTIC_POLICY_REVIEW', 'DETECTION_RULE_REVIEW', 'PROTECTED_FIELD_INVESTIGATION', 'RULE_VERSION_REVIEW', 'TRUST_REEVALUATION', 'SOURCE_MAPPING_REVIEW', 'GOVERNANCE_REVIEW', 'ACCESS_CONTROL_REVIEW'",
    )

    priority_score = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Deterministic priority score between 0 and 100",
    )

    priority_classification = Column(
        String(32),
        nullable=False,
        comment="Priority rating: 'IMMEDIATE' (90-100), 'URGENT' (75-89), 'HIGH' (50-74), 'MEDIUM' (25-49), 'LOW' (0-24)",
    )

    severity = Column(
        String(32),
        nullable=False,
        comment="Severity rating: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    status = Column(
        String(32),
        nullable=False,
        default="GENERATED",
        comment="Lifecycle state: 'GENERATED', 'RECOMMENDED', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'VERIFIED', 'REJECTED'",
    )

    expected_risk_reduction = Column(
        Float,
        nullable=False,
        default=0.0,
        comment="Predicted posture score improvement delta (in points) from hypothetical simulation",
    )

    simulation_confidence = Column(
        Float,
        nullable=False,
        default=1.0,
        comment="Deterministic confidence level of the simulation (0.0 to 1.0)",
    )

    related_posture_snapshot_id = Column(
        String(64),
        nullable=True,
        comment="Link to posture snapshot context if evaluated against posture run",
    )

    related_correlation_id = Column(
        String(64),
        ForeignKey("sentinel.risk_correlations.correlation_id", ondelete="SET NULL"),
        nullable=True,
        comment="Link to generating risk correlation record",
    )

    affected_fields = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of canonical fields targeted by this remediation",
    )

    affected_rules = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of detection rule IDs impacted by this remediation",
    )

    affected_policies = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of semantic policy IDs targeted by this remediation",
    )

    root_cause_candidates = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of identified root causes or drift alerts",
    )

    deterministic_reasoning = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Itemized mathematical factor breakdown and step-by-step logic",
    )

    created_by = Column(
        String(64),
        nullable=False,
        default="SYSTEM_DETERMINISTIC_ENGINE",
        comment="Identity of creator or service",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC timestamp when candidate was generated",
    )

    updated_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
        comment="UTC timestamp when candidate was last updated",
    )

    # Relationships
    actions = relationship(
        "RemediationAction",
        back_populates="remediation",
        cascade="all, delete-orphan",
        order_by="RemediationAction.created_at.asc()",
        lazy="joined",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert remediation candidate to dictionary."""
        return {
            "id": self.id,
            "remediation_id": self.remediation_id,
            "title": self.title,
            "description": self.description,
            "remediation_type": self.remediation_type,
            "priority_score": self.priority_score,
            "priority_classification": self.priority_classification,
            "severity": self.severity,
            "status": self.status,
            "expected_risk_reduction": round(self.expected_risk_reduction, 2),
            "simulation_confidence": round(self.simulation_confidence, 2),
            "related_posture_snapshot_id": self.related_posture_snapshot_id,
            "related_correlation_id": self.related_correlation_id,
            "affected_fields": self.affected_fields or [],
            "affected_rules": self.affected_rules or [],
            "affected_policies": self.affected_policies or [],
            "root_cause_candidates": self.root_cause_candidates or [],
            "deterministic_reasoning": self.deterministic_reasoning or {},
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "action_count": len(self.actions) if self.actions else 0,
        }


class RemediationAction(Base):
    """
    Auditable log of lifecycle transitions, simulations, and governance reviews for remediation candidates.
    """

    __tablename__ = "remediation_actions"
    __table_args__ = (
        Index("ix_rem_action_action_id", "action_id", unique=True),
        Index("ix_rem_action_remediation_id", "remediation_id"),
        Index("ix_rem_action_performed_by", "performed_by"),
        Index("ix_rem_action_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    action_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"raction_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the remediation action log (e.g. raction_...)",
    )

    remediation_id = Column(
        String(64),
        ForeignKey("sentinel.remediation_candidates.remediation_id", ondelete="CASCADE"),
        nullable=False,
        comment="Foreign key to target remediation candidate",
    )

    action_type = Column(
        String(64),
        nullable=False,
        comment="Action category: 'STATUS_CHANGE', 'SIMULATION_EXECUTED', 'GOVERNANCE_REVIEW', 'MITIGATION_VERIFIED'",
    )

    from_status = Column(
        String(32),
        nullable=True,
        comment="State prior to transition",
    )

    to_status = Column(
        String(32),
        nullable=False,
        comment="State after transition",
    )

    performed_by = Column(
        String(64),
        nullable=False,
        comment="User identity handle who performed the action",
    )

    reason = Column(
        Text,
        nullable=True,
        comment="Operational rationale or governance review comment",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC timestamp of the action",
    )

    # Relationship
    remediation = relationship("RemediationCandidate", back_populates="actions")

    def to_dict(self) -> Dict[str, Any]:
        """Convert action record to dictionary."""
        return {
            "id": self.id,
            "action_id": self.action_id,
            "remediation_id": self.remediation_id,
            "action_type": self.action_type,
            "from_status": self.from_status,
            "to_status": self.to_status,
            "performed_by": self.performed_by,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
