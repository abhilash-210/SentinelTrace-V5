"""
models/executive_security_intelligence.py
-----------------------------------------
SQLAlchemy ORM models for Unified Executive Security Intelligence, Executive Risk Posture,
Domain Scoring Breakdown, Ranked Executive Risk Drivers, Posture Trend Snapshots,
and Deterministic Executive Security Insights.

Sprint 10A — Unified Security Intelligence & Executive Risk Posture Command Center.
Core Invariant: "EXECUTIVE SECURITY INTELLIGENCE MUST BE EXPLAINABLE, DETERMINISTIC, AND TRACEABLE BACK TO CRYPTOGRAPHIC EVIDENCE."
Zero Trust Rule: "UNKNOWN != HEALTHY", "CRYPTOGRAPHIC INTEGRITY FAILURE ALWAYS DOMINATES NUMERICAL POSTURE SCORES"
"""

from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship as orm_relationship
from sqlalchemy.types import JSON

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


EXECUTIVE_POSTURE_DOMAIN_PREFIX = "SENTINELTRACE_EXECUTIVE_POSTURE_V1"
EXECUTIVE_INSIGHT_DOMAIN_PREFIX = "SENTINELTRACE_EXECUTIVE_INSIGHT_V1"


def calculate_executive_hash(domain_prefix: str, payload: Any) -> str:
    """Deterministic canonical JSON SHA-256 hash calculation for executive security intelligence."""
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    combined = f"{domain_prefix}{canonical_json}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


class ExecutiveSecurityPostureEvaluation(Base):
    """
    Represents a deterministic point-in-time composite evaluation of the entire SentinelTrace security ecosystem.
    Evaluations are strictly immutable — historical records are never updated in place.
    """

    __tablename__ = "executive_security_posture_evaluations"
    __table_args__ = (
        Index("ix_espe_status_eval_ts", "overall_posture_status", "evaluation_timestamp"),
        Index("ix_espe_eval_hash", "evaluation_hash"),
        Index("ix_espe_eval_ts", "evaluation_timestamp"),
        Index("ix_espe_evaluation_id", "evaluation_id"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"espe-{uuid.uuid4().hex[:12]}",
        comment="Primary key identifier",
    )
    evaluation_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"espe-{uuid.uuid4().hex[:12]}",
        comment="Canonical evaluation identifier",
    )
    evaluation_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        comment="UTC timestamp when the evaluation was executed",
    )
    overall_posture_status = Column(
        String(32),
        nullable=False,
        comment="Status: HEALTHY, GUARDED, ELEVATED, DEGRADED, CRITICAL, UNKNOWN",
    )
    overall_security_score = Column(
        Float,
        nullable=False,
        comment="Composite security posture score (0.0 to 100.0)",
    )
    executive_risk_score = Column(
        Float,
        nullable=False,
        comment="Executive risk score (100.0 - overall_security_score)",
    )
    confidence_score = Column(
        Float,
        nullable=False,
        default=100.0,
        comment="Confidence in posture evaluation based on telemetry completeness (0.0 to 100.0)",
    )
    critical_driver_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of active CRITICAL severity risk drivers",
    )
    high_driver_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of active HIGH severity risk drivers",
    )
    medium_driver_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of active MEDIUM severity risk drivers",
    )
    open_critical_incidents = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of active open CRITICAL incidents",
    )
    open_high_incidents = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of active open HIGH incidents",
    )
    unresolved_assurance_alerts = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of unresolved assurance alerts",
    )
    active_detection_trust_failures = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of detection rules with degraded or failed trust",
    )
    critical_semantic_drift_events = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of unresolved critical semantic drift alerts",
    )
    open_remediation_cases = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of active assurance remediation cases",
    )
    cryptographic_integrity_status = Column(
        String(32),
        nullable=False,
        default="VERIFIED",
        comment="Cryptographic integrity status: VERIFIED, COMPROMISED, UNKNOWN",
    )
    previous_evaluation_id = Column(
        String(64),
        nullable=True,
        comment="Pointer to previous ExecutiveSecurityPostureEvaluation",
    )
    score_delta = Column(
        Float,
        nullable=True,
        comment="Change in overall security score compared to previous evaluation",
    )
    posture_change = Column(
        String(64),
        nullable=True,
        comment="Posture transition: SIGNIFICANT_IMPROVEMENT, IMPROVEMENT, STABLE, DETERIORATION, SIGNIFICANT_DETERIORATION, INITIAL_EVALUATION",
    )
    evaluation_reason = Column(
        Text,
        nullable=False,
        default="",
        comment="Deterministic explanation for overall posture score and status",
    )
    canonical_payload = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Deterministic canonical payload used for SHA-256 seal calculation",
    )
    evaluation_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash sealed with SENTINELTRACE_EXECUTIVE_POSTURE_V1 prefix",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    domain_scores = orm_relationship(
        "ExecutivePostureDomainScore",
        back_populates="evaluation",
        cascade="all, delete-orphan",
        lazy="joined",
    )
    risk_drivers = orm_relationship(
        "ExecutiveRiskDriver",
        back_populates="evaluation",
        cascade="all, delete-orphan",
        lazy="joined",
    )
    insights = orm_relationship(
        "ExecutiveSecurityInsight",
        back_populates="evaluation",
        cascade="all, delete-orphan",
        lazy="joined",
    )
    trend_snapshots = orm_relationship(
        "ExecutivePostureTrendSnapshot",
        back_populates="evaluation",
        cascade="all, delete-orphan",
        lazy="select",
    )


class ExecutivePostureDomainScore(Base):
    """
    Represents domain-level contribution to the overall executive posture.
    Immutable breakdown across the 10 security domains.
    """

    __tablename__ = "executive_posture_domain_scores"
    __table_args__ = (
        Index("ix_epds_eval_domain", "posture_evaluation_id", "domain_name"),
        Index("ix_epds_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"epds-{uuid.uuid4().hex[:12]}",
        comment="Primary key identifier",
    )
    posture_evaluation_id = Column(
        String(64),
        ForeignKey(
            "sentinel.executive_security_posture_evaluations.evaluation_id",
            ondelete="CASCADE",
        ),
        nullable=False,
        comment="Foreign key to executive posture evaluation",
    )
    domain_name = Column(
        String(64),
        nullable=False,
        comment="Domain: EVIDENCE_INTEGRITY, NORMALIZATION, SEMANTIC_TRUST, DETECTION_TRUST, RISK_INTELLIGENCE, INCIDENT_SECURITY, INCIDENT_RESPONSE, PLATFORM_ASSURANCE, ASSURANCE_RECOVERY, CRYPTOGRAPHIC_ASSURANCE",
    )
    base_score = Column(
        Float,
        nullable=False,
        default=100.0,
        comment="Starting base score before deductions (100.0)",
    )
    deduction_total = Column(
        Float,
        nullable=False,
        default=0.0,
        comment="Sum of deterministic deductions in this domain",
    )
    final_score = Column(
        Float,
        nullable=False,
        comment="Final domain score clamped to [0.0, 100.0]",
    )
    risk_weight = Column(
        Float,
        nullable=False,
        comment="Domain risk weight (e.g. 0.15 for 15%)",
    )
    weighted_contribution = Column(
        Float,
        nullable=False,
        comment="Weighted contribution to overall score (final_score * risk_weight)",
    )
    status = Column(
        String(32),
        nullable=False,
        comment="Domain status: HEALTHY, GUARDED, ELEVATED, DEGRADED, CRITICAL, UNKNOWN",
    )
    critical_flag = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether this domain is in a CRITICAL state",
    )
    unknown_flag = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether telemetry for this domain is missing or UNKNOWN",
    )
    primary_driver = Column(
        String(255),
        nullable=False,
        default="NORMAL_OPERATIONS",
        comment="Primary driver or reason for current domain score",
    )
    explanation = Column(
        Text,
        nullable=False,
        default="",
        comment="Deterministic explanation for domain deductions and status",
    )
    canonical_payload = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Detailed domain telemetry breakdown",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    evaluation = orm_relationship(
        "ExecutiveSecurityPostureEvaluation",
        back_populates="domain_scores",
    )


class ExecutiveRiskDriver(Base):
    """
    Represents a specific deterministic reason contributing to executive risk.
    Every driver strictly references its originating source entity — NO orphan conclusions.
    """

    __tablename__ = "executive_risk_drivers"
    __table_args__ = (
        Index("ix_erd_eval_rank", "posture_evaluation_id", "rank"),
        Index("ix_erd_severity_active", "severity", "active"),
        Index("ix_erd_driver_type", "driver_type"),
        Index("ix_erd_driver_id", "driver_id"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"erd-{uuid.uuid4().hex[:12]}",
        comment="Primary key identifier",
    )
    driver_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"erd-{uuid.uuid4().hex[:12]}",
        comment="Unique risk driver identifier",
    )
    posture_evaluation_id = Column(
        String(64),
        ForeignKey(
            "sentinel.executive_security_posture_evaluations.evaluation_id",
            ondelete="CASCADE",
        ),
        nullable=False,
        comment="Foreign key to executive posture evaluation",
    )
    driver_type = Column(
        String(64),
        nullable=False,
        comment="Type: OPEN_CRITICAL_INCIDENT, DETECTION_TRUST_FAILURE, CRYPTOGRAPHIC_INTEGRITY_FAILURE, UNRESOLVED_ASSURANCE_ALERT, SEMANTIC_DRIFT_CRITICAL, FAILED_RECOVERY_VERIFICATION, PENDING_HIGH_IMPACT_CONTAINMENT, TELEMETRY_GAP, MULTI_DOMAIN_ASSURANCE_DEGRADATION, RISK_CORRELATION_SPIKE, etc.",
    )
    severity = Column(
        String(32),
        nullable=False,
        comment="Severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL",
    )
    risk_points = Column(
        Float,
        nullable=False,
        comment="Deterministic risk points contributed by this driver",
    )
    domain = Column(
        String(64),
        nullable=False,
        comment="Domain associated with this risk driver",
    )
    title = Column(
        String(255),
        nullable=False,
        comment="Concise human-readable risk driver title",
    )
    explanation = Column(
        Text,
        nullable=False,
        comment="Detailed deterministic explanation of risk impact",
    )
    source_entity_type = Column(
        String(64),
        nullable=False,
        comment="Source entity type (e.g. SECURITY_INCIDENT, DETECTION_RULE_TRUST, ASSURANCE_ALERT, etc.)",
    )
    source_entity_id = Column(
        String(128),
        nullable=False,
        comment="Identifier of source entity",
    )
    source_reference = Column(
        String(255),
        nullable=False,
        comment="Human readable reference code or URI (e.g. INC-2026-000001, drule-powershell)",
    )
    rank = Column(
        Integer,
        nullable=False,
        default=1,
        comment="Priority rank ordered by severity and risk points",
    )
    active = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether the risk driver is currently active",
    )
    resolved = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether the risk driver has been resolved",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    evaluation = orm_relationship(
        "ExecutiveSecurityPostureEvaluation",
        back_populates="risk_drivers",
    )


class ExecutivePostureTrendSnapshot(Base):
    """
    Stores immutable posture trend data for time-series analysis and historical comparison.
    """

    __tablename__ = "executive_posture_trend_snapshots"
    __table_args__ = (
        Index("ix_epts_timestamp", "timestamp"),
        Index("ix_epts_posture_status", "posture_status"),
        Index("ix_epts_snapshot_id", "snapshot_id"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"epts-{uuid.uuid4().hex[:12]}",
        comment="Primary key identifier",
    )
    snapshot_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"epts-{uuid.uuid4().hex[:12]}",
        comment="Unique snapshot identifier",
    )
    posture_evaluation_id = Column(
        String(64),
        ForeignKey(
            "sentinel.executive_security_posture_evaluations.evaluation_id",
            ondelete="CASCADE",
        ),
        nullable=False,
        comment="Foreign key to executive posture evaluation",
    )
    timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        comment="UTC timestamp of the trend snapshot",
    )
    overall_security_score = Column(
        Float,
        nullable=False,
        comment="Overall security score at snapshot time",
    )
    executive_risk_score = Column(
        Float,
        nullable=False,
        comment="Executive risk score at snapshot time",
    )
    posture_status = Column(
        String(32),
        nullable=False,
        comment="Posture status at snapshot time",
    )
    critical_driver_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of active critical drivers",
    )
    open_incident_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of open incidents",
    )
    assurance_score = Column(
        Float,
        nullable=False,
        default=100.0,
        comment="Platform assurance score component",
    )
    detection_trust_score = Column(
        Float,
        nullable=False,
        default=100.0,
        comment="Detection trust score component",
    )
    cryptographic_status = Column(
        String(32),
        nullable=False,
        default="VERIFIED",
        comment="Cryptographic integrity status",
    )
    score_delta = Column(
        Float,
        nullable=True,
        comment="Score change compared to previous snapshot",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    evaluation = orm_relationship(
        "ExecutiveSecurityPostureEvaluation",
        back_populates="trend_snapshots",
    )


class ExecutiveSecurityInsight(Base):
    """
    Represents deterministic executive-level insights generated via strict rule-based logic (NO ML, NO LLM).
    Every insight provides supporting metrics, affected source domains, confidence, and recommended attention.
    """

    __tablename__ = "executive_security_insights"
    __table_args__ = (
        Index("ix_esi_type_sev", "insight_type", "severity"),
        Index("ix_esi_eval_id", "posture_evaluation_id"),
        Index("ix_esi_insight_id", "insight_id"),
        Index("ix_esi_insight_hash", "insight_hash"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"esi-{uuid.uuid4().hex[:12]}",
        comment="Primary key identifier",
    )
    insight_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"esi-{uuid.uuid4().hex[:12]}",
        comment="Unique insight identifier",
    )
    posture_evaluation_id = Column(
        String(64),
        ForeignKey(
            "sentinel.executive_security_posture_evaluations.evaluation_id",
            ondelete="CASCADE",
        ),
        nullable=False,
        comment="Foreign key to executive posture evaluation",
    )
    insight_type = Column(
        String(64),
        nullable=False,
        comment="Type: RISK_ESCALATION, RISK_IMPROVEMENT, POSTURE_DEGRADATION, POSTURE_RECOVERY, CONCENTRATED_RISK, CROSS_DOMAIN_FAILURE, CRYPTOGRAPHIC_ALERT, TELEMETRY_INSUFFICIENCY, GOVERNANCE_BOTTLENECK",
    )
    severity = Column(
        String(32),
        nullable=False,
        comment="Severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL",
    )
    title = Column(
        String(255),
        nullable=False,
        comment="Insight headline title",
    )
    description = Column(
        Text,
        nullable=False,
        comment="Deterministic insight description grounded in observed metrics",
    )
    supporting_metrics = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Structured supporting metrics and threshold comparisons",
    )
    recommended_attention = Column(
        Text,
        nullable=False,
        comment="Recommended executive or SOC attention",
    )
    source_domains = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of security domains contributing to this insight",
    )
    confidence = Column(
        Float,
        nullable=False,
        default=100.0,
        comment="Confidence percentage for this insight (0.0 to 100.0)",
    )
    canonical_payload = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Deterministic canonical payload used for hash sealing",
    )
    insight_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash sealed with SENTINELTRACE_EXECUTIVE_INSIGHT_V1",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    evaluation = orm_relationship(
        "ExecutiveSecurityPostureEvaluation",
        back_populates="insights",
    )
