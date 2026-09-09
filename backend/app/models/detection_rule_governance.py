"""
models/detection_rule_governance.py
-----------------------------------
SQLAlchemy ORM models for Detection Rule Governance, Dual-Control Approval,
Rule Versioning, Version Impact Analysis, and Immutable Governance Auditability.

Sprint 6C — Detection Rule Governance, Approval Workflow & Version Impact Management.

Core Governance Invariants:
1. Maker-Checker Separation: Creator of a version CANNOT approve the same version.
2. Immutability: An ACTIVE detection rule is never modified in place; all changes produce new versions.
3. Approval != Activation: Approval and Activation remain distinct lifecycle stages.
4. Single ACTIVE Version: Only one version of a rule can be ACTIVE at any time; activation atomically supersedes previous ACTIVE versions.
5. Tamper-Evident Audit: Every governance action produces a cryptographically hashed immutable governance event.
"""

import uuid
from datetime import datetime, timezone
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
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON

from app.database import Base


class DetectionRuleVersion(Base):
    """
    Immutable version snapshot for a detection rule.
    Captures complete governed rule definitions, dependencies, and lifecycle approvals.
    """

    __tablename__ = "detection_rule_versions"
    __table_args__ = (
        Index("ix_rule_versions_version_id", "version_id", unique=True),
        Index("ix_rule_versions_rule_id", "rule_id"),
        Index("ix_rule_versions_status", "status"),
        Index("ix_rule_versions_version_hash", "version_hash"),
        UniqueConstraint("rule_id", "version_number", name="uq_rule_version_number"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    version_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"drver_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for this version snapshot (e.g. 'drver_cisco_asa_v2')",
    )

    rule_id = Column(
        String(64),
        ForeignKey("sentinel.detection_rules.rule_id", ondelete="CASCADE"),
        nullable=False,
        comment="Parent detection rule identifier",
    )

    version_number = Column(
        Integer,
        nullable=False,
        comment="Monotonically increasing version number for this rule (1, 2, 3...)",
    )

    parent_version_id = Column(
        String(64),
        nullable=True,
        comment="Immediate parent version ID this version was branched or modified from",
    )

    rule_name = Column(
        String(255),
        nullable=False,
        comment="Governed human-readable rule title",
    )

    vendor_name = Column(
        String(255),
        nullable=False,
        comment="Originating vendor scope (e.g. 'Cisco ASA', 'Windows Security')",
    )

    description = Column(
        Text,
        nullable=True,
        comment="Governed technical description and detection objective",
    )

    query_signature = Column(
        Text,
        nullable=True,
        comment="Governed query pattern, signature, or logic expression",
    )

    severity = Column(
        String(32),
        nullable=False,
        default="MEDIUM",
        comment="Governed severity rating: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    mitre_techniques = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of MITRE ATT&CK technique IDs (e.g. ['T1078', 'T1190'])",
    )

    status = Column(
        String(32),
        nullable=False,
        default="DRAFT",
        comment="Lifecycle state: 'DRAFT', 'PENDING_REVIEW', 'APPROVED', 'REJECTED', 'ACTIVE', 'SUPERSEDED', 'DISABLED'",
    )

    # Authorship & Review tracking
    created_by_user_id = Column(
        String(64),
        nullable=False,
        comment="User ID who created this draft version",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC timestamp when draft was created",
    )

    submitted_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when submitted for review",
    )

    submitted_by_user_id = Column(
        String(64),
        nullable=True,
        comment="User ID who submitted this version for review",
    )

    reviewed_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp of maker-checker review decision",
    )

    reviewed_by_user_id = Column(
        String(64),
        nullable=True,
        comment="User ID who reviewed this version (MUST NOT equal created_by_user_id)",
    )

    approval_decision = Column(
        String(32),
        nullable=True,
        comment="Review decision: 'APPROVED' or 'REJECTED'",
    )

    approval_comment = Column(
        Text,
        nullable=True,
        comment="Reviewer audit notes explaining approval or rejection reason",
    )

    risk_acknowledged = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether reviewer explicitly acknowledged simulated trust risks (if AT_RISK/INVALID)",
    )

    risk_acknowledgement_comment = Column(
        Text,
        nullable=True,
        comment="Reviewer justification for approving an AT_RISK or degraded version",
    )

    activated_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when this version was activated in production",
    )

    activated_by_user_id = Column(
        String(64),
        nullable=True,
        comment="User ID who authorized activation",
    )

    superseded_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when superseded by a newer active version",
    )

    superseded_by_version_id = Column(
        String(64),
        nullable=True,
        comment="Version ID of the newer version that replaced this one",
    )

    version_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash sealing this governed version definition",
    )

    # Relationships
    rule = relationship("DetectionRule", foreign_keys=[rule_id], lazy="joined")
    dependencies = relationship(
        "DetectionRuleVersionDependency",
        back_populates="version",
        cascade="all, delete-orphan",
        lazy="joined",
    )
    approval_requests = relationship(
        "DetectionRuleApprovalRequest",
        back_populates="version",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert version record to dictionary."""
        return {
            "id": self.id,
            "version_id": self.version_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "version_number": self.version_number,
            "parent_version_id": self.parent_version_id,
            "vendor_name": self.vendor_name,
            "description": self.description,
            "query_signature": self.query_signature,
            "severity": self.severity,
            "mitre_techniques": self.mitre_techniques or [],
            "status": self.status,
            "created_by_user_id": self.created_by_user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "submitted_by_user_id": self.submitted_by_user_id,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "reviewed_by_user_id": self.reviewed_by_user_id,
            "approval_decision": self.approval_decision,
            "approval_comment": self.approval_comment,
            "risk_acknowledged": self.risk_acknowledged,
            "risk_acknowledgement_comment": self.risk_acknowledgement_comment,
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "activated_by_user_id": self.activated_by_user_id,
            "superseded_at": self.superseded_at.isoformat() if self.superseded_at else None,
            "superseded_by_version_id": self.superseded_by_version_id,
            "version_hash": self.version_hash,
            "dependencies": [d.to_dict() for d in self.dependencies] if self.dependencies else [],
        }


class DetectionRuleVersionDependency(Base):
    """
    Version-scoped snapshot of a canonical field dependency.
    Ensures historical versions retain their exact dependency contracts regardless of future registry changes.
    """

    __tablename__ = "detection_rule_version_dependencies"
    __table_args__ = (
        Index("ix_ver_deps_version_id", "version_id"),
        Index("ix_ver_deps_canonical_field", "canonical_field"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    version_id = Column(
        String(64),
        ForeignKey("sentinel.detection_rule_versions.version_id", ondelete="CASCADE"),
        nullable=False,
        comment="Foreign key to parent detection rule version",
    )

    canonical_field = Column(
        String(100),
        nullable=False,
        comment="Canonical field required by this version (e.g. 'action.result', 'src_endpoint_ip')",
    )

    dependency_type = Column(
        String(32),
        nullable=False,
        default="REQUIRED",
        comment="Dependency classification: 'REQUIRED', 'OPTIONAL', 'ENRICHMENT'",
    )

    is_protected_field = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether this canonical field is a protected semantic asset",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC creation timestamp",
    )

    # Parent relationship
    version = relationship("DetectionRuleVersion", back_populates="dependencies")

    def to_dict(self) -> Dict[str, Any]:
        """Convert version dependency to dictionary."""
        return {
            "id": self.id,
            "version_id": self.version_id,
            "canonical_field": self.canonical_field,
            "dependency_type": self.dependency_type,
            "is_protected_field": self.is_protected_field,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DetectionRuleApprovalRequest(Base):
    """
    Explicit dual-control approval request tracking maker-checker governance.
    """

    __tablename__ = "detection_rule_approval_requests"
    __table_args__ = (
        Index("ix_dr_approval_req_id", "approval_request_id", unique=True),
        Index("ix_dr_approval_version_id", "version_id"),
        Index("ix_dr_approval_rule_id", "rule_id"),
        Index("ix_dr_approval_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    approval_request_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"drapp_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the approval request",
    )

    version_id = Column(
        String(64),
        ForeignKey("sentinel.detection_rule_versions.version_id", ondelete="CASCADE"),
        nullable=False,
        comment="Target rule version awaiting dual-control decision",
    )

    rule_id = Column(
        String(64),
        ForeignKey("sentinel.detection_rules.rule_id", ondelete="CASCADE"),
        nullable=False,
        comment="Target detection rule",
    )

    submitted_by_user_id = Column(
        String(64),
        nullable=False,
        comment="Author user ID who submitted the version for review",
    )

    submitted_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC submission timestamp",
    )

    status = Column(
        String(32),
        nullable=False,
        default="PENDING",
        comment="Approval status: 'PENDING', 'APPROVED', 'REJECTED', 'CANCELLED'",
    )

    reviewed_by_user_id = Column(
        String(64),
        nullable=True,
        comment="Independent reviewer user ID (Maker-Checker invariant: != submitted_by)",
    )

    reviewed_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC review timestamp",
    )

    decision = Column(
        String(32),
        nullable=True,
        comment="Review decision: 'APPROVED' or 'REJECTED'",
    )

    review_comment = Column(
        Text,
        nullable=True,
        comment="Reviewer audit comment",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC record creation timestamp",
    )

    # Relationships
    version = relationship("DetectionRuleVersion", back_populates="approval_requests")
    rule = relationship("DetectionRule", foreign_keys=[rule_id], lazy="joined")

    def to_dict(self) -> Dict[str, Any]:
        """Convert approval request to dictionary."""
        return {
            "id": self.id,
            "approval_request_id": self.approval_request_id,
            "version_id": self.version_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule.rule_name if self.rule else None,
            "submitted_by_user_id": self.submitted_by_user_id,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "status": self.status,
            "reviewed_by_user_id": self.reviewed_by_user_id,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "decision": self.decision,
            "review_comment": self.review_comment,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DetectionRuleVersionImpact(Base):
    """
    Stored deterministic impact comparison between a source version and a target candidate version.
    """

    __tablename__ = "detection_rule_version_impacts"
    __table_args__ = (
        Index("ix_ver_impact_impact_id", "impact_id", unique=True),
        Index("ix_ver_impact_source_id", "source_version_id"),
        Index("ix_ver_impact_target_id", "target_version_id"),
        Index("ix_ver_impact_level", "impact_level"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    impact_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"drvi_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the version impact analysis",
    )

    source_version_id = Column(
        String(64),
        nullable=True,
        comment="Baseline version ID (None if initial version v1)",
    )

    target_version_id = Column(
        String(64),
        ForeignKey("sentinel.detection_rule_versions.version_id", ondelete="CASCADE"),
        nullable=False,
        comment="Candidate version ID being analyzed",
    )

    impact_level = Column(
        String(32),
        nullable=False,
        comment="Overall calculated impact level: 'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    query_changed = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether detection query logic/signature changed",
    )

    severity_changed = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether rule severity level changed",
    )

    vendor_scope_changed = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether vendor applicability scope changed",
    )

    mitre_changed = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether MITRE ATT&CK techniques changed",
    )

    dependencies_added = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of canonical fields added in candidate version",
    )

    dependencies_removed = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of canonical fields removed in candidate version",
    )

    protected_fields_added = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of protected semantic fields introduced in candidate version",
    )

    trust_risk_delta = Column(
        Float,
        default=0.0,
        nullable=False,
        comment="Simulated trust score delta (negative means degradation)",
    )

    blast_radius_summary = Column(
        Text,
        nullable=False,
        comment="Human-readable summary of downstream detection and semantic implications",
    )

    impact_details = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Detailed dictionary of all component comparisons",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC creation timestamp",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert version impact record to dictionary."""
        return {
            "id": self.id,
            "impact_id": self.impact_id,
            "source_version_id": self.source_version_id,
            "target_version_id": self.target_version_id,
            "impact_level": self.impact_level,
            "query_changed": self.query_changed,
            "severity_changed": self.severity_changed,
            "vendor_scope_changed": self.vendor_scope_changed,
            "mitre_changed": self.mitre_changed,
            "dependencies_added": self.dependencies_added or [],
            "dependencies_removed": self.dependencies_removed or [],
            "protected_fields_added": self.protected_fields_added or [],
            "trust_risk_delta": round(self.trust_risk_delta, 4),
            "blast_radius_summary": self.blast_radius_summary,
            "impact_details": self.impact_details or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DetectionRuleGovernanceEvent(Base):
    """
    Immutable governance audit event sealing who did what, when, and with what cryptographic proof.
    """

    __tablename__ = "detection_rule_governance_events"
    __table_args__ = (
        Index("ix_dr_gov_events_event_id", "event_id", unique=True),
        Index("ix_dr_gov_events_rule_id", "rule_id"),
        Index("ix_dr_gov_events_version_id", "version_id"),
        Index("ix_dr_gov_events_event_type", "event_type"),
        Index("ix_dr_gov_events_actor", "actor_user_id"),
        Index("ix_dr_gov_events_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    event_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"drgov_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the governance audit event",
    )

    rule_id = Column(
        String(64),
        nullable=False,
        comment="Associated detection rule ID",
    )

    version_id = Column(
        String(64),
        nullable=True,
        comment="Associated rule version ID (if version-scoped)",
    )

    event_type = Column(
        String(64),
        nullable=False,
        comment="Category: 'RULE_CREATED', 'RULE_VERSION_CREATED', 'RULE_SUBMITTED_FOR_REVIEW', 'RULE_APPROVED', 'RULE_REJECTED', 'RULE_ACTIVATED', 'RULE_SUPERSEDED', 'RULE_DISABLED', 'SELF_APPROVAL_BLOCKED', 'VERSION_IMPACT_ANALYZED'",
    )

    actor_user_id = Column(
        String(64),
        nullable=False,
        comment="User ID of the actor initiating the governance action",
    )

    actor_role = Column(
        String(32),
        nullable=False,
        comment="RBAC role of the actor at time of action",
    )

    previous_status = Column(
        String(32),
        nullable=True,
        comment="Version/Rule status before this governance action",
    )

    new_status = Column(
        String(32),
        nullable=True,
        comment="Version/Rule status resulting from this governance action",
    )

    event_payload = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Canonical metadata payload sealed in event hash",
    )

    event_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash sealing this governance event",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC creation timestamp",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert governance event to dictionary."""
        return {
            "id": self.id,
            "event_id": self.event_id,
            "rule_id": self.rule_id,
            "version_id": self.version_id,
            "event_type": self.event_type,
            "actor_user_id": self.actor_user_id,
            "actor_role": self.actor_role,
            "previous_status": self.previous_status,
            "new_status": self.new_status,
            "event_payload": self.event_payload or {},
            "event_hash": self.event_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
