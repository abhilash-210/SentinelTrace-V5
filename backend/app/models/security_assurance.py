"""
models/security_assurance.py
-----------------------------
SQLAlchemy ORM models for Continuous Security Assurance, Domain Evaluations,
Platform Assurance Snapshots, Assurance Alerts, Metric Definitions, and Trend Snapshots.

Sprint 9A — Continuous Security Assurance & Platform Health Intelligence.
Core Invariant: "SENTINELTRACE MUST MONITOR THE TRUSTWORTHINESS OF ITS OWN SECURITY PIPELINE."
"""

from datetime import datetime, timezone
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


class AssuranceDomainEvaluation(Base):
    """
    Immutable point-in-time evaluation snapshot of one assurance domain.
    Never updated in-place; re-evaluations produce new immutable records.
    """

    __tablename__ = "assurance_domain_evaluations"
    __table_args__ = (
        Index("ix_ade_domain_eval_ts", "domain_name", "evaluation_timestamp"),
        Index("ix_ade_status_eval_ts", "status", "evaluation_timestamp"),
        Index("ix_ade_evaluation_hash", "evaluation_hash"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"ade-{uuid.uuid4().hex[:12]}",
        comment="Unique domain evaluation identifier",
    )
    domain_name = Column(
        String(64),
        nullable=False,
        comment="Domain: EVIDENCE_ASSURANCE, NORMALIZATION_ASSURANCE, SEMANTIC_ASSURANCE, DETECTION_ASSURANCE, RISK_ASSURANCE, INCIDENT_RESPONSE_ASSURANCE, CRYPTOGRAPHIC_ASSURANCE",
    )
    evaluation_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        comment="UTC timestamp when domain was evaluated",
    )
    score = Column(
        Float,
        nullable=False,
        comment="Evaluated score between 0.00 and 100.00",
    )
    status = Column(
        String(32),
        nullable=False,
        comment="Status: HEALTHY, DEGRADED, AT_RISK, CRITICAL, UNKNOWN",
    )
    metric_snapshot = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Detailed metric telemetry snapshot captured at evaluation time",
    )
    deductions = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="Array of transparent deduction items: {reason, deduction, severity, metric_key, details}",
    )
    explanation = Column(
        Text,
        nullable=False,
        default="",
        comment="Deterministic explainability summary for domain score",
    )
    risk_level = Column(
        String(32),
        nullable=False,
        default="LOW",
        comment="Assessed risk level: LOW, MEDIUM, HIGH, CRITICAL",
    )
    evaluation_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash of canonical domain evaluation payload",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )


class PlatformAssuranceEvaluation(Base):
    """
    Platform-wide composite assurance evaluation snapshot.
    Combines all 7 assurance domains with weighted scoring and hard failure overrides.
    """

    __tablename__ = "platform_assurance_evaluations"
    __table_args__ = (
        Index("ix_pae_status_eval_ts", "overall_status", "evaluation_timestamp"),
        Index("ix_pae_eval_hash", "evaluation_hash"),
        Index("ix_pae_eval_ts", "evaluation_timestamp"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"pae-{uuid.uuid4().hex[:12]}",
        comment="Unique platform assurance evaluation identifier",
    )
    evaluation_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        comment="UTC timestamp of platform evaluation",
    )
    overall_score = Column(
        Float,
        nullable=False,
        comment="Overall platform trust score between 0.00 and 100.00",
    )
    overall_status = Column(
        String(32),
        nullable=False,
        comment="Overall platform status: HEALTHY, DEGRADED, AT_RISK, CRITICAL, UNKNOWN",
    )
    evidence_score = Column(
        Float,
        nullable=False,
        comment="Evidence assurance domain score",
    )
    normalization_score = Column(
        Float,
        nullable=False,
        comment="Normalization assurance domain score",
    )
    semantic_score = Column(
        Float,
        nullable=False,
        comment="Semantic assurance domain score",
    )
    detection_score = Column(
        Float,
        nullable=False,
        comment="Detection assurance domain score",
    )
    risk_score = Column(
        Float,
        nullable=False,
        comment="Risk assurance domain score",
    )
    incident_response_score = Column(
        Float,
        nullable=False,
        comment="Incident response assurance domain score",
    )
    cryptographic_score = Column(
        Float,
        nullable=False,
        comment="Cryptographic assurance domain score",
    )
    domain_weights = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Weights applied across the 7 assurance domains",
    )
    score_breakdown = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Complete domain score breakdown and evaluation references",
    )
    critical_conditions = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of hard failure conditions or critical triggers triggered",
    )
    explanation = Column(
        Text,
        nullable=False,
        default="",
        comment="Deterministic explainability summary for platform score",
    )
    evaluation_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 seal hash of canonical platform evaluation payload",
    )
    previous_evaluation_id = Column(
        String(64),
        nullable=True,
        comment="Pointer to previous PlatformAssuranceEvaluation for chained cryptographic provenance",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )


class AssuranceAlert(Base):
    """
    Actionable assurance degradation and trust regression alert.
    Deduplicated via deterministic SHA-256 keys to avoid unbounded alert floods.
    """

    __tablename__ = "assurance_alerts"
    __table_args__ = (
        Index("ix_aa_status_severity", "status", "severity"),
        Index("ix_aa_dedup_key", "deduplication_key"),
        Index("ix_aa_domain", "domain_name"),
        Index("ix_aa_alert_type", "alert_type"),
        Index("ix_aa_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"aa-{uuid.uuid4().hex[:12]}",
        comment="Unique assurance alert identifier",
    )
    alert_type = Column(
        String(64),
        nullable=False,
        comment="Type: ASSURANCE_DEGRADED, ASSURANCE_AT_RISK, ASSURANCE_CRITICAL, SCORE_REGRESSION, CRYPTOGRAPHIC_INTEGRITY_FAILURE, PIPELINE_TRUST_FAILURE, STALE_SECURITY_OPERATION",
    )
    domain_name = Column(
        String(64),
        nullable=False,
        comment="Target assurance domain",
    )
    severity = Column(
        String(32),
        nullable=False,
        comment="Severity: LOW, MEDIUM, HIGH, CRITICAL",
    )
    status = Column(
        String(32),
        nullable=False,
        default="OPEN",
        comment="Status: OPEN, ACKNOWLEDGED, RESOLVED",
    )
    title = Column(
        String(255),
        nullable=False,
        comment="Short actionable alert title",
    )
    description = Column(
        Text,
        nullable=False,
        default="",
        comment="Comprehensive alert narrative and root cause guidance",
    )
    source_evaluation_id = Column(
        String(64),
        nullable=True,
        comment="Reference to triggering PlatformAssuranceEvaluation or AssuranceDomainEvaluation",
    )
    previous_score = Column(
        Float,
        nullable=True,
        comment="Previous domain/platform score before regression",
    )
    current_score = Column(
        Float,
        nullable=False,
        comment="Current score when alert fired",
    )
    score_delta = Column(
        Float,
        nullable=True,
        comment="Magnitude of score drop (e.g. -15.0)",
    )
    deduplication_key = Column(
        String(64),
        nullable=False,
        comment="SHA-256 hash of domain + alert_type + source_condition",
    )
    first_detected_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        comment="Timestamp when alert condition was first observed",
    )
    last_detected_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        comment="Timestamp when alert condition was most recently observed",
    )
    acknowledged_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of acknowledgment",
    )
    acknowledged_by = Column(
        String(64),
        nullable=True,
        comment="User ID who acknowledged alert",
    )
    resolved_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of resolution",
    )
    resolved_by = Column(
        String(64),
        nullable=True,
        comment="User ID who marked alert resolved",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )


class AssuranceMetricDefinition(Base):
    """
    Deterministic metric catalog and threshold configuration.
    Historical evaluations store metric snapshots; future config changes never rewrite history.
    """

    __tablename__ = "assurance_metric_definitions"
    __table_args__ = (
        Index("ix_amd_metric_key", "metric_key", unique=True),
        Index("ix_amd_domain", "domain_name"),
        Index("ix_amd_enabled", "enabled"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"amd-{uuid.uuid4().hex[:12]}",
        comment="Metric definition ID",
    )
    metric_key = Column(
        String(64),
        nullable=False,
        unique=True,
        comment="Deterministic unique key e.g. 'evidence.hash_mismatch'",
    )
    domain_name = Column(
        String(64),
        nullable=False,
        comment="Assurance domain",
    )
    metric_name = Column(
        String(255),
        nullable=False,
        comment="Human-readable metric name",
    )
    description = Column(
        Text,
        nullable=False,
        default="",
        comment="Metric purpose and measurement criteria",
    )
    weight = Column(
        Float,
        nullable=False,
        default=1.0,
        comment="Relative weight / deduction multiplier",
    )
    healthy_threshold = Column(
        Float,
        nullable=False,
        default=0.0,
        comment="Upper bound for healthy state",
    )
    degraded_threshold = Column(
        Float,
        nullable=False,
        default=1.0,
        comment="Threshold for degraded classification",
    )
    at_risk_threshold = Column(
        Float,
        nullable=False,
        default=5.0,
        comment="Threshold for at-risk classification",
    )
    critical_threshold = Column(
        Float,
        nullable=False,
        default=10.0,
        comment="Threshold for critical classification",
    )
    enabled = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether this metric is actively evaluated",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )


class AssuranceTrendSnapshot(Base):
    """
    Time-series trend snapshot for platform and domain assurance history.
    """

    __tablename__ = "assurance_trend_snapshots"
    __table_args__ = (
        Index("ix_ats_snapshot_ts", "snapshot_timestamp"),
        Index("ix_ats_platform_eval_id", "platform_evaluation_id"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"ats-{uuid.uuid4().hex[:12]}",
        comment="Trend snapshot ID",
    )
    platform_evaluation_id = Column(
        String(64),
        nullable=False,
        comment="Reference to PlatformAssuranceEvaluation",
    )
    snapshot_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        comment="Timestamp of trend snapshot",
    )
    overall_score = Column(
        Float,
        nullable=False,
        comment="Overall platform score",
    )
    overall_status = Column(
        String(32),
        nullable=False,
        comment="Overall platform status",
    )
    domain_scores = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Dictionary of domain -> score at snapshot time",
    )
    score_delta = Column(
        Float,
        nullable=True,
        comment="Score delta compared to prior evaluation",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
