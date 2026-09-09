"""
models/semantic_policy.py
-------------------------
SQLAlchemy ORM models for the Semantic Policy Registry and Protected Semantic Fields.

Sprint 3A — Semantic Policy Registry & Backend Management.
Enforces vendor/source-profile-scoped semantic interpretation to prevent global
semantic assumptions while safeguarding critical security-sensitive fields.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class SemanticPolicy(Base):
    """
    Semantic Policy definition governing field-level interpretations for a specific vendor/source.
    """

    __tablename__ = "semantic_policies"
    __table_args__ = (
        Index("ix_semantic_policies_policy_id", "policy_id", unique=True),
        Index("ix_semantic_policies_vendor_name", "vendor_name"),
        Index("ix_semantic_policies_source_profile_id", "source_profile_id"),
        Index("ix_semantic_policies_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    policy_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"spol_{uuid.uuid4().hex[:12]}",
        comment="Unique human-readable policy identifier (e.g. 'spol_cisco_asa_v1')",
    )

    policy_name = Column(
        String(255),
        nullable=False,
        comment="Human-readable policy title",
    )

    vendor_name = Column(
        String(255),
        nullable=False,
        comment="Originating vendor or product family (e.g. 'Cisco ASA')",
    )

    source_profile_id = Column(
        String(64),
        nullable=False,
        comment="Associated structural Source Profile identifier",
    )

    version = Column(
        Integer,
        nullable=False,
        default=1,
        comment="Incremental policy version number",
    )

    status = Column(
        String(32),
        nullable=False,
        default="DRAFT",
        comment="Lifecycle state: 'DRAFT', 'ACTIVE', 'SUPERSEDED', 'RETIRED'",
    )

    description = Column(
        Text,
        nullable=True,
        comment="Technical documentation and rationale for policy interpretation",
    )

    supersedes_policy_id = Column(
        String(64),
        nullable=True,
        comment="Identifier of prior policy version superseded by this release",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC creation timestamp",
    )

    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC last update timestamp",
    )

    # Relationship to rules
    rules = relationship(
        "SemanticPolicyRule",
        back_populates="policy",
        cascade="all, delete-orphan",
        lazy="joined",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to summary dictionary."""
        return {
            "id": self.id,
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "vendor_name": self.vendor_name,
            "source_profile_id": self.source_profile_id,
            "version": self.version,
            "status": self.status,
            "description": self.description,
            "supersedes_policy_id": self.supersedes_policy_id,
            "rule_count": len(self.rules) if self.rules is not None else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "rules": [rule.to_dict() for rule in self.rules] if self.rules is not None else [],
        }


class SemanticPolicyRule(Base):
    """
    Individual semantic mapping rule scoped exclusively to its parent SemanticPolicy.
    """

    __tablename__ = "semantic_policy_rules"
    __table_args__ = (
        Index("ix_semantic_policy_rules_rule_id", "rule_id", unique=True),
        Index("ix_semantic_policy_rules_policy_id", "policy_id"),
        Index("ix_semantic_policy_rules_source_field", "source_field"),
        Index("ix_semantic_policy_rules_canonical_field", "canonical_field"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    rule_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"srule_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for rule (e.g. 'srule_01')",
    )

    policy_id = Column(
        String(64),
        ForeignKey("sentinel.semantic_policies.policy_id", ondelete="CASCADE"),
        nullable=False,
        comment="Foreign key linking to parent SemanticPolicy.policy_id",
    )

    source_field = Column(
        String(100),
        nullable=False,
        comment="Raw source field name (e.g. 'action')",
    )

    source_value = Column(
        String(255),
        nullable=False,
        comment="Raw vendor value (e.g. 'PERMIT', 'ALLOW', 'BLOCK')",
    )

    canonical_field = Column(
        String(100),
        nullable=False,
        comment="Target canonical field name (e.g. 'action.result')",
    )

    canonical_value = Column(
        String(255),
        nullable=False,
        comment="Mapped canonical value (e.g. 'ALLOWED', 'DENIED', 'MONITORED')",
    )

    equivalence_classification = Column(
        String(32),
        nullable=False,
        default="EQUIVALENT",
        comment="Equivalence level: 'EQUIVALENT', 'COMPATIBLE', 'AMBIGUOUS', 'INCOMPATIBLE'",
    )

    risk_level = Column(
        String(32),
        nullable=False,
        default="LOW",
        comment="Risk rating: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    description = Column(
        Text,
        nullable=True,
        comment="Rule rationale and edge-case documentation",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC creation timestamp",
    )

    # Parent relationship
    policy = relationship("SemanticPolicy", back_populates="rules")

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary representation."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "policy_id": self.policy_id,
            "source_field": self.source_field,
            "source_value": self.source_value,
            "canonical_field": self.canonical_field,
            "canonical_value": self.canonical_value,
            "equivalence_classification": self.equivalence_classification,
            "risk_level": self.risk_level,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ProtectedSemanticField(Base):
    """
    Security-sensitive canonical fields that require elevated governance and auditability.
    """

    __tablename__ = "protected_semantic_fields"
    __table_args__ = (
        Index("ix_protected_semantic_fields_field_name", "field_name", unique=True),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate key",
    )

    field_name = Column(
        String(100),
        unique=True,
        nullable=False,
        comment="Canonical field path (e.g. 'action.result', 'severity')",
    )

    criticality = Column(
        String(32),
        nullable=False,
        default="HIGH",
        comment="Criticality classification: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'",
    )

    description = Column(
        Text,
        nullable=False,
        comment="Security significance explanation",
    )

    is_protected = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether field is protected from unauthenticated/ungoverned modifications",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC creation timestamp",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert protected field to dictionary representation."""
        return {
            "id": self.id,
            "field_name": self.field_name,
            "criticality": self.criticality,
            "description": self.description,
            "is_protected": self.is_protected,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
