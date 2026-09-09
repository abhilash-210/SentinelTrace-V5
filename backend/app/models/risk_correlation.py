"""
models/risk_correlation.py
--------------------------
SQLAlchemy ORM models for Risk Correlations, Concentration Clusters, and Graph Members.

Sprint 7B — Security Posture Risk Correlation, Prioritized Remediation & Executive Risk Intelligence.
Deterministically correlates security findings (drift alerts, trust alerts, invalid/at-risk rules,
protected semantic field violations) and identifies concentrated risk clusters without opaque scoring.
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


class RiskCorrelation(Base):
    """
    Deterministic correlation entity grouping multi-dimensional security signals into
    verifiable risk chains and concentration clusters.
    """

    __tablename__ = "risk_correlations"
    __table_args__ = (
        Index("ix_risk_corr_correlation_id", "correlation_id", unique=True),
        Index("ix_risk_corr_type", "correlation_type"),
        Index("ix_risk_corr_severity", "severity"),
        Index("ix_risk_corr_status", "status"),
        Index("ix_risk_corr_cluster_key", "risk_cluster_key"),
        Index("ix_risk_corr_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    correlation_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"rcorr_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the risk correlation record (e.g. rcorr_...)",
    )

    correlation_type = Column(
        String(64),
        nullable=False,
        comment="Category: 'SINGLE_SIGNAL', 'MULTI_SIGNAL', 'DEPENDENCY_CHAIN', 'PROTECTED_FIELD_CHAIN', 'TRUST_DEGRADATION_CHAIN', 'CRITICAL_RISK_CLUSTER'",
    )

    severity = Column(
        String(32),
        nullable=False,
        comment="Severity rating: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    status = Column(
        String(32),
        nullable=False,
        default="ACTIVE",
        comment="Lifecycle status: 'ACTIVE', 'INVESTIGATING', 'MITIGATED', 'CLOSED'",
    )

    risk_cluster_key = Column(
        String(128),
        nullable=True,
        comment="Grouping key for concentrated risk (e.g. 'cluster_action.result', 'cluster_cisco_asa')",
    )

    affected_signal_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of contributing telemetry, drift, and trust signals",
    )

    affected_rule_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of downstream impacted detection rules",
    )

    affected_field_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of affected canonical / protected fields",
    )

    risk_score = Column(
        Float,
        nullable=False,
        default=0.0,
        comment="Deterministic composite risk score between 0.0 and 100.0",
    )

    root_cause_candidates = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="Ordered list of candidate root cause entities (e.g. drift alerts, mapping gaps)",
    )

    explanation = Column(
        Text,
        nullable=False,
        comment="Comprehensive human-readable and mathematically explainable description of correlation",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC timestamp when correlation was identified",
    )

    # Relationships
    members = relationship(
        "RiskCorrelationMember",
        back_populates="correlation",
        cascade="all, delete-orphan",
        lazy="joined",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert correlation record to dictionary."""
        return {
            "id": self.id,
            "correlation_id": self.correlation_id,
            "correlation_type": self.correlation_type,
            "severity": self.severity,
            "status": self.status,
            "risk_cluster_key": self.risk_cluster_key,
            "affected_signal_count": self.affected_signal_count,
            "affected_rule_count": self.affected_rule_count,
            "affected_field_count": self.affected_field_count,
            "risk_score": round(self.risk_score, 2),
            "root_cause_candidates": self.root_cause_candidates or [],
            "explanation": self.explanation,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "member_count": len(self.members) if self.members else 0,
        }


class RiskCorrelationMember(Base):
    """
    Association table mapping signals, rules, fields, and events into a correlation graph.
    """

    __tablename__ = "risk_correlation_members"
    __table_args__ = (
        Index("ix_risk_member_corr_id", "correlation_id"),
        Index("ix_risk_member_type_id", "member_type", "member_id"),
        Index("ix_risk_member_rel_type", "relationship_type"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    correlation_id = Column(
        String(64),
        ForeignKey("sentinel.risk_correlations.correlation_id", ondelete="CASCADE"),
        nullable=False,
        comment="Foreign key to parent risk correlation",
    )

    member_type = Column(
        String(64),
        nullable=False,
        comment="Entity type: 'SEMANTIC_DRIFT_ALERT', 'DETECTION_TRUST_ALERT', 'TRUST_EVALUATION', 'DETECTION_RULE', 'CANONICAL_FIELD', 'PROTECTED_FIELD', 'GOVERNANCE_VIOLATION', 'DETECTION_EXECUTION', 'RAW_EVIDENCE', 'NORMALIZED_EVENT'",
    )

    member_id = Column(
        String(128),
        nullable=False,
        comment="Identifier or canonical name of member (e.g. 'alert_...', 'drule_...', 'action.result')",
    )

    relationship_type = Column(
        String(64),
        nullable=False,
        comment="Relationship role: 'CONTRIBUTING_FACTOR', 'DIRECT_DEPENDENCY', 'DOWNSTREAM_IMPACT', 'ROOT_CAUSE_CANDIDATE', 'GOVERNANCE_ANCHOR'",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC timestamp when membership was established",
    )

    # Relationship
    correlation = relationship("RiskCorrelation", back_populates="members")

    def to_dict(self) -> Dict[str, Any]:
        """Convert member record to dictionary."""
        return {
            "id": self.id,
            "correlation_id": self.correlation_id,
            "member_type": self.member_type,
            "member_id": self.member_id,
            "relationship_type": self.relationship_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
