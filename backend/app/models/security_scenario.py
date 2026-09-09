"""
models/security_scenario.py
---------------------------
SQLAlchemy ORM models for End-to-End Security Scenario Orchestration,
Demonstration Validation, Cross-Domain Artifact Binding, Scenario Verification,
Executive Impact Comparison, and Cross-Domain Evidence Replay.

Sprint 10B — End-to-End Security Scenario Orchestration, Demonstration Validation & Cross-Domain Evidence Replay.
Core Invariant: "EVERY EXECUTIVE SECURITY CONCLUSION MUST BE REPLAYABLE BACKWARD THROUGH THE COMPLETE SECURITY PIPELINE TO ITS ORIGINAL EVIDENCE."
Zero Trust Invariants: "DEMONSTRATION != SYNTHETIC TRUST", "REPLAY != RECOMPUTATION WITHOUT PROOF", "UNKNOWN != SUCCESS", "BROKEN PROVENANCE INVALIDATES SCENARIO"
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
from sqlalchemy.orm import relationship as orm_relationship
from sqlalchemy.types import JSON

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


SCENARIO_VERSION_DOMAIN_PREFIX = "SENTINELTRACE_SCENARIO_VERSION_V1"
SCENARIO_EXECUTION_DOMAIN_PREFIX = "SENTINELTRACE_SCENARIO_EXECUTION_V1"
SCENARIO_ARTIFACT_BINDING_DOMAIN_PREFIX = "SENTINELTRACE_SCENARIO_ARTIFACT_BINDING_V1"
SCENARIO_VERIFICATION_DOMAIN_PREFIX = "SENTINELTRACE_SCENARIO_VERIFICATION_V1"
SCENARIO_REPLAY_DOMAIN_PREFIX = "SENTINELTRACE_SCENARIO_REPLAY_V1"


def calculate_scenario_hash(domain_prefix: str, payload: Any) -> str:
    """Deterministic canonical JSON SHA-256 hash calculation for scenario orchestration."""
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    combined = f"{domain_prefix}{canonical_json}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


class SecurityScenario(Base):
    """
    Logical reusable security scenario definition entity.
    Represents a narrative arc across the SentinelTrace 10-domain architecture.
    """
    __tablename__ = "security_scenarios"
    __table_args__ = (
        Index("ix_security_scenarios_key", "scenario_key", unique=True),
        Index("ix_security_scenarios_category", "category"),
        Index("ix_security_scenarios_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"scn_{uuid.uuid4().hex[:16]}",
        nullable=False,
    )
    scenario_key = Column(String(128), unique=True, nullable=False)
    scenario_name = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(64), nullable=False)  # e.g., IDENTITY_COMPROMISE, ENDPOINT_MALWARE, TRUST_DEGRADATION, CRYPTO_VERIFICATION
    severity = Column(String(32), nullable=False, default="HIGH")  # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(32), nullable=False, default="DRAFT")  # DRAFT, ACTIVE, RETIRED

    current_version_id = Column(String(64), nullable=True)

    created_by_user_id = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    versions = orm_relationship(
        "SecurityScenarioVersion",
        back_populates="scenario",
        cascade="all, delete-orphan",
        order_by="SecurityScenarioVersion.version_number.desc()",
    )
    executions = orm_relationship(
        "ScenarioExecution",
        back_populates="scenario",
        order_by="ScenarioExecution.started_at.desc()",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scenario_key": self.scenario_key,
            "scenario_name": self.scenario_name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "current_version_id": self.current_version_id,
            "created_by_user_id": self.created_by_user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class SecurityScenarioVersion(Base):
    """
    Immutable version snapshot of a scenario definition.
    Sealed with SHA-256 (SENTINELTRACE_SCENARIO_VERSION_V1).
    """
    __tablename__ = "security_scenario_versions"
    __table_args__ = (
        UniqueConstraint("scenario_id", "version_number", name="uq_scenario_version_number"),
        Index("ix_scenario_versions_scenario_id", "scenario_id"),
        Index("ix_scenario_versions_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"scnv_{uuid.uuid4().hex[:16]}",
        nullable=False,
    )
    scenario_id = Column(
        String(64),
        ForeignKey("sentinel.security_scenarios.id", ondelete="CASCADE"),
        nullable=False,
    )
    version_number = Column(Integer, nullable=False)
    scenario_definition_json = Column(JSON, nullable=False, default=dict)
    expected_stage_sequence_json = Column(JSON, nullable=False, default=list)
    expected_outcomes_json = Column(JSON, nullable=False, default=dict)
    deterministic_seed = Column(String(128), nullable=False)
    definition_hash = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="DRAFT")  # DRAFT, ACTIVE, SUPERSEDED
    created_by_user_id = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    scenario = orm_relationship("SecurityScenario", back_populates="versions")
    executions = orm_relationship("ScenarioExecution", back_populates="version")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scenario_id": self.scenario_id,
            "version_number": self.version_number,
            "scenario_definition_json": self.scenario_definition_json,
            "expected_stage_sequence_json": self.expected_stage_sequence_json,
            "expected_outcomes_json": self.expected_outcomes_json,
            "deterministic_seed": self.deterministic_seed,
            "definition_hash": self.definition_hash,
            "status": self.status,
            "created_by_user_id": self.created_by_user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScenarioExecution(Base):
    """
    Controlled execution of a scenario version.
    Tracks progression through all 20 canonical stages.
    """
    __tablename__ = "scenario_executions"
    __table_args__ = (
        Index("ix_scenario_executions_number", "execution_number", unique=True),
        Index("ix_scenario_executions_scenario_id", "scenario_id"),
        Index("ix_scenario_executions_status", "status"),
        Index("ix_scenario_executions_mode", "execution_mode"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"scx_{uuid.uuid4().hex[:16]}",
        nullable=False,
    )
    execution_number = Column(String(64), unique=True, nullable=False)  # SCX-YYYY-NNN
    scenario_id = Column(
        String(64),
        ForeignKey("sentinel.security_scenarios.id"),
        nullable=False,
    )
    scenario_version_id = Column(
        String(64),
        ForeignKey("sentinel.security_scenario_versions.id"),
        nullable=False,
    )
    execution_mode = Column(String(32), nullable=False, default="CONTROLLED_DEMO")  # LIVE_PIPELINE, CONTROLLED_DEMO, HISTORICAL_REPLAY
    status = Column(String(32), nullable=False, default="CREATED")  # CREATED, RUNNING, PAUSED, COMPLETED, FAILED, CANCELLED
    started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    initiated_by_user_id = Column(String(64), nullable=False)
    deterministic_execution_seed = Column(String(128), nullable=False)
    execution_hash = Column(String(64), nullable=False)
    verification_status = Column(String(32), nullable=False, default="UNVERIFIED")  # UNVERIFIED, VERIFIED, DEGRADED, FAILED

    # Relationships
    scenario = orm_relationship("SecurityScenario", back_populates="executions")
    version = orm_relationship("SecurityScenarioVersion", back_populates="executions")
    stages = orm_relationship(
        "ScenarioStageExecution",
        back_populates="execution",
        cascade="all, delete-orphan",
        order_by="ScenarioStageExecution.stage_number.asc()",
    )
    artifact_bindings = orm_relationship(
        "ScenarioArtifactBinding",
        back_populates="execution",
        cascade="all, delete-orphan",
    )
    verification_result = orm_relationship(
        "ScenarioVerificationResult",
        back_populates="execution",
        uselist=False,
        cascade="all, delete-orphan",
    )
    executive_impact = orm_relationship(
        "ScenarioExecutiveImpact",
        back_populates="execution",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "execution_number": self.execution_number,
            "scenario_id": self.scenario_id,
            "scenario_version_id": self.scenario_version_id,
            "execution_mode": self.execution_mode,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "initiated_by_user_id": self.initiated_by_user_id,
            "deterministic_execution_seed": self.deterministic_execution_seed,
            "execution_hash": self.execution_hash,
            "verification_status": self.verification_status,
        }


class ScenarioStageExecution(Base):
    """
    Records execution of a specific stage (1 through 20) in a scenario execution run.
    """
    __tablename__ = "scenario_stage_executions"
    __table_args__ = (
        Index("ix_stage_executions_scenario_exec", "scenario_execution_id"),
        Index("ix_stage_executions_stage_num", "scenario_execution_id", "stage_number"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"scs_{uuid.uuid4().hex[:16]}",
        nullable=False,
    )
    scenario_execution_id = Column(
        String(64),
        ForeignKey("sentinel.scenario_executions.id", ondelete="CASCADE"),
        nullable=False,
    )
    stage_number = Column(Integer, nullable=False)
    stage_key = Column(String(64), nullable=False)
    stage_name = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False, default="PENDING")  # PENDING, RUNNING, COMPLETED, SKIPPED, FAILED
    started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    input_reference_json = Column(JSON, nullable=False, default=dict)
    output_reference_json = Column(JSON, nullable=False, default=dict)
    verification_result = Column(String(32), nullable=False, default="UNVERIFIED")  # UNVERIFIED, VERIFIED, DEGRADED, FAILED
    error_code = Column(String(64), nullable=True)
    execution_hash = Column(String(64), nullable=False)

    # Relationships
    execution = orm_relationship("ScenarioExecution", back_populates="stages")
    artifact_bindings = orm_relationship(
        "ScenarioArtifactBinding",
        back_populates="stage_execution",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scenario_execution_id": self.scenario_execution_id,
            "stage_number": self.stage_number,
            "stage_key": self.stage_key,
            "stage_name": self.stage_name,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "input_reference_json": self.input_reference_json,
            "output_reference_json": self.output_reference_json,
            "verification_result": self.verification_result,
            "error_code": self.error_code,
            "execution_hash": self.execution_hash,
        }


class ScenarioArtifactBinding(Base):
    """
    Connects scenario execution stages to existing immutable platform artifacts.
    Stores cryptographic references only — does not duplicate immutable artifacts.
    """
    __tablename__ = "scenario_artifact_bindings"
    __table_args__ = (
        Index("ix_artifact_bindings_exec_id", "scenario_execution_id"),
        Index("ix_artifact_bindings_stage_id", "stage_execution_id"),
        Index("ix_artifact_bindings_artifact_id", "artifact_id"),
        Index("ix_artifact_bindings_domain", "artifact_domain"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"sab_{uuid.uuid4().hex[:16]}",
        nullable=False,
    )
    scenario_execution_id = Column(
        String(64),
        ForeignKey("sentinel.scenario_executions.id", ondelete="CASCADE"),
        nullable=False,
    )
    stage_execution_id = Column(
        String(64),
        ForeignKey("sentinel.scenario_stage_executions.id", ondelete="CASCADE"),
        nullable=False,
    )
    artifact_domain = Column(String(64), nullable=False)  # EVIDENCE, NORMALIZATION, SEMANTICS, DETECTION, RISK, INCIDENT, RESPONSE, ASSURANCE, RECOVERY, EXECUTIVE, CRYPTO
    artifact_type = Column(String(64), nullable=False)    # RAW_LOG, NORMALIZED_EVENT, SEMANTIC_POLICY, DETECTION_RULE, RISK_CORRELATION, SECURITY_INCIDENT, CONTAINMENT_REQUEST, ASSURANCE_EVALUATION, EXECUTIVE_POSTURE, LEDGER_ENTRY
    artifact_id = Column(String(128), nullable=False)
    artifact_hash = Column(String(64), nullable=False)
    artifact_reference_json = Column(JSON, nullable=False, default=dict)
    binding_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    execution = orm_relationship("ScenarioExecution", back_populates="artifact_bindings")
    stage_execution = orm_relationship("ScenarioStageExecution", back_populates="artifact_bindings")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scenario_execution_id": self.scenario_execution_id,
            "stage_execution_id": self.stage_execution_id,
            "artifact_domain": self.artifact_domain,
            "artifact_type": self.artifact_type,
            "artifact_id": self.artifact_id,
            "artifact_hash": self.artifact_hash,
            "artifact_reference_json": self.artifact_reference_json,
            "binding_hash": self.binding_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScenarioVerificationResult(Base):
    """
    Immutable end-to-end cryptographic and structural verification result of a scenario execution.
    Sealed with SHA-256 (SENTINELTRACE_SCENARIO_VERIFICATION_V1).
    """
    __tablename__ = "scenario_verification_results"
    __table_args__ = (
        Index("ix_scenario_verif_exec_id", "scenario_execution_id", unique=True),
        Index("ix_scenario_verif_status", "overall_verification_status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"svr_{uuid.uuid4().hex[:16]}",
        nullable=False,
    )
    scenario_execution_id = Column(
        String(64),
        ForeignKey("sentinel.scenario_executions.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    total_stages = Column(Integer, nullable=False, default=20)
    verified_stages = Column(Integer, nullable=False, default=0)
    degraded_stages = Column(Integer, nullable=False, default=0)
    failed_stages = Column(Integer, nullable=False, default=0)
    missing_stages = Column(Integer, nullable=False, default=0)

    provenance_integrity = Column(String(32), nullable=False, default="UNVERIFIED")  # VERIFIED, DEGRADED, FAILED
    ledger_integrity = Column(String(32), nullable=False, default="UNVERIFIED")      # VERIFIED, FAILED
    merkle_integrity = Column(String(32), nullable=False, default="UNVERIFIED")      # VERIFIED, FAILED
    overall_verification_status = Column(String(32), nullable=False, default="UNVERIFIED")  # VERIFIED, DEGRADED, FAILED

    verification_summary_json = Column(JSON, nullable=False, default=dict)
    verification_hash = Column(String(64), nullable=False)
    verified_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    verified_by_user_id = Column(String(64), nullable=False)

    # Relationships
    execution = orm_relationship("ScenarioExecution", back_populates="verification_result")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scenario_execution_id": self.scenario_execution_id,
            "total_stages": self.total_stages,
            "verified_stages": self.verified_stages,
            "degraded_stages": self.degraded_stages,
            "failed_stages": self.failed_stages,
            "missing_stages": self.missing_stages,
            "provenance_integrity": self.provenance_integrity,
            "ledger_integrity": self.ledger_integrity,
            "merkle_integrity": self.merkle_integrity,
            "overall_verification_status": self.overall_verification_status,
            "verification_summary_json": self.verification_summary_json,
            "verification_hash": self.verification_hash,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "verified_by_user_id": self.verified_by_user_id,
        }


class ScenarioExecutiveImpact(Base):
    """
    Captures how a scenario execution altered executive security posture scores and risk drivers.
    """
    __tablename__ = "scenario_executive_impacts"
    __table_args__ = (
        Index("ix_scenario_impact_exec_id", "scenario_execution_id", unique=True),
        Index("ix_scenario_impact_classification", "impact_classification"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"sei_{uuid.uuid4().hex[:16]}",
        nullable=False,
    )
    scenario_execution_id = Column(
        String(64),
        ForeignKey("sentinel.scenario_executions.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    pre_executive_posture_id = Column(String(64), nullable=True)
    post_executive_posture_id = Column(String(64), nullable=True)

    pre_score = Column(Float, nullable=False, default=100.0)
    post_score = Column(Float, nullable=False, default=100.0)
    score_delta = Column(Float, nullable=False, default=0.0)

    pre_status = Column(String(32), nullable=False, default="HEALTHY")
    post_status = Column(String(32), nullable=False, default="HEALTHY")

    impacted_domains_json = Column(JSON, nullable=False, default=list)
    top_risk_driver_delta_json = Column(JSON, nullable=False, default=list)
    impact_classification = Column(String(32), nullable=False, default="NEUTRAL")  # CRITICAL_NEGATIVE, HIGH_NEGATIVE, MODERATE_NEGATIVE, LOW_NEGATIVE, NEUTRAL, POSITIVE_RECOVERY

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    execution = orm_relationship("ScenarioExecution", back_populates="executive_impact")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scenario_execution_id": self.scenario_execution_id,
            "pre_executive_posture_id": self.pre_executive_posture_id,
            "post_executive_posture_id": self.post_executive_posture_id,
            "pre_score": self.pre_score,
            "post_score": self.post_score,
            "score_delta": self.score_delta,
            "pre_status": self.pre_status,
            "post_status": self.post_status,
            "impacted_domains_json": self.impacted_domains_json,
            "top_risk_driver_delta_json": self.top_risk_driver_delta_json,
            "impact_classification": self.impact_classification,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
