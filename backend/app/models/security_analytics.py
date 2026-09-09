"""
models/security_analytics.py
----------------------------
SQLAlchemy ORM models for Unified Security Analytics, Reporting & Evidence Intelligence.

Sprint 12B — Security Analytics, Reporting & Evidence Intelligence.
Core Invariant: "SECURITY METRICS WITHOUT EVIDENCE ARE NUMBERS.
SECURITY METRICS WITH TRACEABLE EVIDENCE BECOME INTELLIGENCE."

Zero-Trust Analytics Axioms:
- NO DATA != GOOD PERFORMANCE
- LOW ALERT COUNT != LOW RISK
- LOW INCIDENT COUNT != HEALTHY SECURITY
- MISSING TELEMETRY != IMPROVEMENT
- AVERAGE SCORE != VERIFIED SECURITY
- REPORT GENERATED != REPORT TRUSTED
- TREND != CAUSATION
- CORRELATION != ROOT CAUSE
- UNKNOWN != HEALTHY
- CRYPTOGRAPHIC FAILURE > NUMERICAL REPORT SCORE
"""

from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
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
from sqlalchemy.orm import relationship as orm_relationship
from sqlalchemy.types import JSON

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


ANALYTICS_SNAPSHOT_DOMAIN_PREFIX = "SENTINELTRACE_ANALYTICS_SNAPSHOT_V1"
SECURITY_METRIC_DOMAIN_PREFIX = "SENTINELTRACE_SECURITY_METRIC_V1"
TREND_SNAPSHOT_DOMAIN_PREFIX = "SENTINELTRACE_SECURITY_TREND_V1"
ANALYTICS_INSIGHT_DOMAIN_PREFIX = "SENTINELTRACE_ANALYTICS_INSIGHT_V1"
SECURITY_REPORT_DOMAIN_PREFIX = "SENTINELTRACE_SECURITY_REPORT_V1"
REPORT_SECTION_DOMAIN_PREFIX = "SENTINELTRACE_REPORT_SECTION_V1"
EVIDENCE_PACKAGE_DOMAIN_PREFIX = "SENTINELTRACE_EVIDENCE_PACKAGE_V1"
EVIDENCE_BINDING_DOMAIN_PREFIX = "SENTINELTRACE_EVIDENCE_PACKAGE_BINDING_V1"
PROVENANCE_DOMAIN_PREFIX = "SENTINELTRACE_ANALYTICS_PROVENANCE_V1"


def compute_canonical_hash(prefix: str, payload: Dict[str, Any]) -> str:
    """Deterministic SHA-256 computation over canonical JSON."""
    raw = prefix + ":" + json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SecurityAnalyticsSnapshot(Base):
    """
    Immutable point-in-time snapshot of cross-domain security analytics.
    """

    __tablename__ = "security_analytics_snapshots"
    __table_args__ = (
        Index("ix_sas_snapshot_number", "snapshot_number", unique=True),
        Index("ix_sas_period_type", "period_type"),
        Index("ix_sas_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"sas-{uuid.uuid4().hex[:12]}",
    )
    snapshot_number = Column(
        String(64),
        nullable=False,
        unique=True,
        comment="Human-readable identifier e.g. SAS-2026-001",
    )
    period_type = Column(
        String(32),
        nullable=False,
        default="24H",
        comment="24H, 7D, 30D, 90D, CUSTOM",
    )
    period_start = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    period_end = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    overall_security_score = Column(
        Float,
        nullable=False,
        default=0.0,
        comment="Composite security score 0.0 - 100.0",
    )
    overall_confidence = Column(
        Float,
        nullable=False,
        default=100.0,
        comment="Analytics confidence score 0.0 - 100.0 based on telemetry",
    )
    telemetry_completeness = Column(
        Float,
        nullable=False,
        default=100.0,
        comment="Percentage of required metrics with available telemetry",
    )
    domains_evaluated = Column(
        Integer,
        nullable=False,
        default=0,
    )
    domains_unknown = Column(
        Integer,
        nullable=False,
        default=0,
    )
    critical_findings = Column(
        Integer,
        nullable=False,
        default=0,
    )
    high_findings = Column(
        Integer,
        nullable=False,
        default=0,
    )
    snapshot_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 seal of canonical snapshot state",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    created_by = Column(
        String(128),
        nullable=False,
        default="SYSTEM",
    )

    # Relationships
    metric_evaluations = orm_relationship(
        "SecurityMetricEvaluation",
        back_populates="snapshot",
        cascade="all, delete-orphan",
        order_by="SecurityMetricEvaluation.created_at",
    )
    insights = orm_relationship(
        "SecurityAnalyticsInsight",
        back_populates="snapshot",
        cascade="all, delete-orphan",
        order_by="SecurityAnalyticsInsight.created_at",
    )
    provenance_records = orm_relationship(
        "SecurityAnalyticsProvenanceRecord",
        back_populates="snapshot",
        cascade="all, delete-orphan",
        order_by="SecurityAnalyticsProvenanceRecord.stage_number",
    )


class SecurityMetricDefinition(Base):
    """
    Registry of cross-domain security metric definitions.
    """

    __tablename__ = "security_metric_definitions"
    __table_args__ = (
        Index("ix_smd_metric_code", "metric_code", unique=True),
        Index("ix_smd_domain", "domain"),
        Index("ix_smd_criticality", "criticality"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"smd-{uuid.uuid4().hex[:12]}",
    )
    metric_code = Column(
        String(64),
        nullable=False,
        unique=True,
        comment="Unique identifier e.g. METRIC_EVIDENCE_INTEGRITY_RATE",
    )
    metric_name = Column(
        String(128),
        nullable=False,
        comment="Display name of the metric",
    )
    description = Column(
        Text,
        nullable=False,
        comment="Detailed metric explanation",
    )
    domain = Column(
        String(64),
        nullable=False,
        comment="Security domain e.g. EVIDENCE, NORMALIZATION, DETECTION, RISK, INCIDENTS, etc.",
    )
    unit = Column(
        String(32),
        nullable=False,
        default="PERCENT",
        comment="PERCENT, COUNT, HOURS, SCORE, INDEX",
    )
    direction = Column(
        String(32),
        nullable=False,
        default="HIGHER_IS_BETTER",
        comment="HIGHER_IS_BETTER, LOWER_IS_BETTER, NEUTRAL",
    )
    calculation_method = Column(
        Text,
        nullable=False,
        comment="Formula and data sources specification",
    )
    criticality = Column(
        String(32),
        nullable=False,
        default="MEDIUM",
        comment="CRITICAL, HIGH, MEDIUM, LOW",
    )
    requires_complete_telemetry = Column(
        Boolean,
        nullable=False,
        default=True,
    )
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    evaluations = orm_relationship(
        "SecurityMetricEvaluation",
        back_populates="definition",
        cascade="all, delete-orphan",
    )


class SecurityMetricEvaluation(Base):
    """
    Evaluated metric record bound to a specific point-in-time snapshot.
    """

    __tablename__ = "security_metric_evaluations"
    __table_args__ = (
        Index("ix_sme_snapshot_id", "snapshot_id"),
        Index("ix_sme_metric_definition_id", "metric_definition_id"),
        Index("ix_sme_status", "metric_status"),
        UniqueConstraint("snapshot_id", "metric_definition_id", name="uq_snapshot_metric_def"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"sme-{uuid.uuid4().hex[:12]}",
    )
    snapshot_id = Column(
        String(64),
        ForeignKey("sentinel.security_analytics_snapshots.id", ondelete="CASCADE"),
        nullable=False,
    )
    metric_definition_id = Column(
        String(64),
        ForeignKey("sentinel.security_metric_definitions.id", ondelete="CASCADE"),
        nullable=False,
    )
    metric_value = Column(
        Float,
        nullable=False,
        comment="Calculated value of the metric",
    )
    metric_status = Column(
        String(32),
        nullable=False,
        default="HEALTHY",
        comment="HEALTHY, GUARDED, DEGRADED, CRITICAL, UNKNOWN",
    )
    confidence_score = Column(
        Float,
        nullable=False,
        default=100.0,
        comment="Evaluation confidence 0.0 - 100.0",
    )
    sample_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of backing data samples analyzed",
    )
    telemetry_state = Column(
        String(32),
        nullable=False,
        default="COMPLETE",
        comment="COMPLETE, PARTIAL, INSUFFICIENT, UNKNOWN",
    )
    calculation_details_json = Column(
        JSON,
        nullable=False,
        default=dict,
        comment="Detailed breakdown of the mathematical evaluation",
    )
    source_references_json = Column(
        JSON,
        nullable=False,
        default=list,
        comment="Array of source entity IDs referenced in evaluation",
    )
    evaluation_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 seal of evaluation payload",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    snapshot = orm_relationship("SecurityAnalyticsSnapshot", back_populates="metric_evaluations")
    definition = orm_relationship("SecurityMetricDefinition", back_populates="evaluations")


class SecurityTrendSnapshot(Base):
    """
    Historical delta and trend classification between metric evaluations.
    """

    __tablename__ = "security_trend_snapshots"
    __table_args__ = (
        Index("ix_sts_metric_def_id", "metric_definition_id"),
        Index("ix_sts_current_snap_id", "current_snapshot_id"),
        Index("ix_sts_classification", "trend_classification"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"sts-{uuid.uuid4().hex[:12]}",
    )
    metric_definition_id = Column(
        String(64),
        ForeignKey("sentinel.security_metric_definitions.id", ondelete="CASCADE"),
        nullable=False,
    )
    current_snapshot_id = Column(
        String(64),
        ForeignKey("sentinel.security_analytics_snapshots.id", ondelete="CASCADE"),
        nullable=False,
    )
    previous_snapshot_id = Column(
        String(64),
        ForeignKey("sentinel.security_analytics_snapshots.id", ondelete="SET NULL"),
        nullable=True,
    )
    current_value = Column(
        Float,
        nullable=False,
    )
    previous_value = Column(
        Float,
        nullable=True,
    )
    delta_value = Column(
        Float,
        nullable=True,
    )
    delta_percentage = Column(
        Float,
        nullable=True,
    )
    trend_classification = Column(
        String(32),
        nullable=False,
        default="STABLE",
        comment="IMPROVING, STABLE, DEGRADING, INSUFFICIENT_DATA",
    )
    confidence = Column(
        Float,
        nullable=False,
        default=100.0,
    )
    reasoning_json = Column(
        JSON,
        nullable=False,
        default=dict,
        comment="Explainable reasoning behind classification",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )


class SecurityAnalyticsInsight(Base):
    """
    Deterministic rule-triggered platform insight with supporting metrics and limitations.
    """

    __tablename__ = "security_analytics_insights"
    __table_args__ = (
        Index("ix_sai_snapshot_id", "snapshot_id"),
        Index("ix_sai_type", "insight_type"),
        Index("ix_sai_severity", "severity"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"sai-{uuid.uuid4().hex[:12]}",
    )
    snapshot_id = Column(
        String(64),
        ForeignKey("sentinel.security_analytics_snapshots.id", ondelete="CASCADE"),
        nullable=False,
    )
    insight_code = Column(
        String(64),
        nullable=False,
        comment="Unique identifier e.g. SAI-CROSS-DOMAIN-001",
    )
    insight_type = Column(
        String(64),
        nullable=False,
        comment="RISK_ESCALATION, DETECTION_DEGRADATION, CROSS_DOMAIN_FAILURE, etc.",
    )
    severity = Column(
        String(32),
        nullable=False,
        default="HIGH",
        comment="CRITICAL, HIGH, MEDIUM, LOW, INFO",
    )
    title = Column(
        String(255),
        nullable=False,
    )
    description = Column(
        Text,
        nullable=False,
    )
    rule_triggered = Column(
        String(128),
        nullable=False,
        comment="Name of deterministic evaluation rule",
    )
    supporting_metrics_json = Column(
        JSON,
        nullable=False,
        default=list,
        comment="List of supporting metric codes and values",
    )
    source_references_json = Column(
        JSON,
        nullable=False,
        default=list,
        comment="Source entity identifiers backing the insight",
    )
    confidence_score = Column(
        Float,
        nullable=False,
        default=100.0,
    )
    limitations_json = Column(
        JSON,
        nullable=False,
        default=list,
        comment="Documented analytic limitations and assumptions",
    )
    insight_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 seal of insight content",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    snapshot = orm_relationship("SecurityAnalyticsSnapshot", back_populates="insights")


class SecurityReport(Base):
    """
    Comprehensive, audit-ready security report entity with cryptographic seal.
    """

    __tablename__ = "security_reports"
    __table_args__ = (
        Index("ix_sr_report_number", "report_number", unique=True),
        Index("ix_sr_report_type", "report_type"),
        Index("ix_sr_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"sr-{uuid.uuid4().hex[:12]}",
    )
    report_number = Column(
        String(64),
        nullable=False,
        unique=True,
        comment="Human-readable identifier e.g. SRP-2026-001",
    )
    report_type = Column(
        String(64),
        nullable=False,
        comment="EXECUTIVE_SECURITY_REPORT, SOC_OPERATIONAL_REPORT, COMPLIANCE_ASSURANCE_REPORT, etc.",
    )
    title = Column(
        String(255),
        nullable=False,
    )
    description = Column(
        Text,
        nullable=False,
    )
    period_start = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    period_end = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    status = Column(
        String(32),
        nullable=False,
        default="DRAFT",
        comment="DRAFT, FINALIZED, VERIFIED, UNTRUSTED",
    )
    generated_by_user_id = Column(
        String(128),
        nullable=False,
        default="SYSTEM",
    )
    generated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    canonical_manifest_json = Column(
        JSON,
        nullable=False,
        default=dict,
        comment="Canonical metadata manifest used for hashing",
    )
    report_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 seal of full report content",
    )
    integrity_status = Column(
        String(32),
        nullable=False,
        default="VERIFIED",
        comment="VERIFIED, DEGRADED, UNTRUSTED, UNKNOWN",
    )
    ledger_reference = Column(
        String(128),
        nullable=True,
        comment="Governance Ledger block hash or commitment reference",
    )
    merkle_reference = Column(
        String(128),
        nullable=True,
        comment="Merkle tree root or inclusion proof reference",
    )

    # Relationships
    sections = orm_relationship(
        "SecurityReportSection",
        back_populates="report",
        cascade="all, delete-orphan",
        order_by="SecurityReportSection.section_order",
    )


class SecurityReportSection(Base):
    """
    Structured section within a security report.
    """

    __tablename__ = "security_report_sections"
    __table_args__ = (
        Index("ix_srs_report_id", "report_id"),
        Index("ix_srs_section_order", "section_order"),
        UniqueConstraint("report_id", "section_order", name="uq_report_section_order"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"srs-{uuid.uuid4().hex[:12]}",
    )
    report_id = Column(
        String(64),
        ForeignKey("sentinel.security_reports.id", ondelete="CASCADE"),
        nullable=False,
    )
    section_order = Column(
        Integer,
        nullable=False,
        comment="Sequential display order (1, 2, 3...)",
    )
    section_type = Column(
        String(64),
        nullable=False,
        comment="EXECUTIVE_SUMMARY, SECURITY_POSTURE, DETECTION_ANALYTICS, etc.",
    )
    title = Column(
        String(255),
        nullable=False,
    )
    summary = Column(
        Text,
        nullable=False,
    )
    content_json = Column(
        JSON,
        nullable=False,
        default=dict,
        comment="Structured payload of section content",
    )
    source_references_json = Column(
        JSON,
        nullable=False,
        default=list,
        comment="Cross-domain evidence source identifiers",
    )
    section_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 hash of section payload",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    report = orm_relationship("SecurityReport", back_populates="sections")


class SecurityEvidencePackage(Base):
    """
    Audit-ready reference-only evidence package bundling cross-domain artifacts.
    """

    __tablename__ = "security_evidence_packages"
    __table_args__ = (
        Index("ix_sep_package_number", "package_number", unique=True),
        Index("ix_sep_package_type", "package_type"),
        Index("ix_sep_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"sep-{uuid.uuid4().hex[:12]}",
    )
    package_number = Column(
        String(64),
        nullable=False,
        unique=True,
        comment="Human-readable identifier e.g. SEP-2026-001",
    )
    package_type = Column(
        String(64),
        nullable=False,
        default="COMPREHENSIVE_AUDIT",
        comment="COMPREHENSIVE_AUDIT, INCIDENT_DOSSIER, COMPLIANCE_ATTESTATION, etc.",
    )
    scope = Column(
        String(128),
        nullable=False,
        default="PLATFORM_FULL",
    )
    description = Column(
        Text,
        nullable=False,
    )
    artifact_count = Column(
        Integer,
        nullable=False,
        default=0,
    )
    manifest_json = Column(
        JSON,
        nullable=False,
        default=dict,
        comment="Canonical manifest containing list of bound artifact references and hashes",
    )
    manifest_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 seal of canonical manifest",
    )
    integrity_status = Column(
        String(32),
        nullable=False,
        default="VERIFIED",
        comment="VERIFIED, DEGRADED, UNTRUSTED, UNKNOWN",
    )
    ledger_reference = Column(
        String(128),
        nullable=True,
    )
    merkle_reference = Column(
        String(128),
        nullable=True,
    )
    created_by_user_id = Column(
        String(128),
        nullable=False,
        default="SYSTEM",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    artifacts = orm_relationship(
        "EvidencePackageArtifact",
        back_populates="package",
        cascade="all, delete-orphan",
        order_by="EvidencePackageArtifact.created_at",
    )


class EvidencePackageArtifact(Base):
    """
    Immutable reference binding pointing to an existing cross-domain artifact.
    """

    __tablename__ = "evidence_package_artifacts"
    __table_args__ = (
        Index("ix_epa_package_id", "package_id"),
        Index("ix_epa_domain", "artifact_domain"),
        Index("ix_epa_artifact_id", "artifact_id"),
        UniqueConstraint("package_id", "artifact_domain", "artifact_id", name="uq_package_artifact_domain_id"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"epa-{uuid.uuid4().hex[:12]}",
    )
    package_id = Column(
        String(64),
        ForeignKey("sentinel.security_evidence_packages.id", ondelete="CASCADE"),
        nullable=False,
    )
    artifact_domain = Column(
        String(64),
        nullable=False,
        comment="RAW_EVIDENCE, NORMALIZATION, DETECTION, INCIDENT, THREAT_INTEL, etc.",
    )
    artifact_type = Column(
        String(64),
        nullable=False,
        comment="Specific type within the domain e.g. RAW_LOG, ALERT, IOC, FINDING",
    )
    artifact_id = Column(
        String(128),
        nullable=False,
        comment="Primary ID of the source entity",
    )
    artifact_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 hash of the referenced artifact at binding time",
    )
    source_reference = Column(
        String(255),
        nullable=False,
        comment="URI or platform path to authoritative record",
    )
    binding_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 seal of this binding entry",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    package = orm_relationship("SecurityEvidencePackage", back_populates="artifacts")


class SecurityAnalyticsProvenanceRecord(Base):
    """
    17-stage cryptographic hash-chained provenance lineage for analytics and reporting.
    """

    __tablename__ = "security_analytics_provenance_records"
    __table_args__ = (
        Index("ix_sapr_snapshot_id", "snapshot_id"),
        Index("ix_sapr_stage_number", "stage_number"),
        UniqueConstraint("snapshot_id", "stage_number", name="uq_snapshot_provenance_stage_number"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"sapr-{uuid.uuid4().hex[:12]}",
    )
    snapshot_id = Column(
        String(64),
        ForeignKey("sentinel.security_analytics_snapshots.id", ondelete="CASCADE"),
        nullable=False,
    )
    stage_number = Column(
        Integer,
        nullable=False,
        comment="Sequential stage order (1..17)",
    )
    stage_name = Column(
        String(64),
        nullable=False,
        comment="Name of lineage stage",
    )
    artifact_type = Column(
        String(64),
        nullable=False,
        comment="Entity type verified at this stage",
    )
    artifact_id = Column(
        String(128),
        nullable=False,
        comment="Entity ID or placeholder e.g. NOT_APPLICABLE",
    )
    artifact_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 hash of stage artifact",
    )
    previous_hash = Column(
        String(64),
        nullable=False,
        comment="Previous stage hash in the chain",
    )
    current_hash = Column(
        String(64),
        nullable=False,
        comment="Current stage cumulative hash in chain",
    )
    verification_status = Column(
        String(32),
        nullable=False,
        default="VERIFIED",
        comment="VERIFIED, DEGRADED, UNTRUSTED, UNKNOWN",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    snapshot = orm_relationship("SecurityAnalyticsSnapshot", back_populates="provenance_records")
