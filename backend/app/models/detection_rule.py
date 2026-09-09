"""
models/detection_rule.py
-------------------------
SQLAlchemy ORM models for the Detection Rule Registry and Canonical Field
Dependency Mapping.

Sprint 6A — Detection Rule Registry & Canonical Field Dependency Mapping.
Registers detection rules with lifecycle governance, vendor scoping, and
explicit declarations of which canonical fields each rule depends upon.

Architectural Principles:
- Detection rules MUST NOT mutate raw evidence or normalized events.
- New detection rules MUST always be created as DRAFT.
- Rules reference canonical fields by name (no FK to normalized_events columns).
- Dependency edges form a DAG from rules to canonical fields for impact analysis.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class DetectionRule(Base):
    """
    Detection rule metadata registered in the Semantic Trust framework.

    Rules are vendor-scoped, lifecycle-governed, and declare explicit
    canonical field dependencies for impact propagation analysis.
    """

    __tablename__ = "detection_rules"
    __table_args__ = (
        Index("ix_detection_rules_rule_id", "rule_id", unique=True),
        Index("ix_detection_rules_vendor_name", "vendor_name"),
        Index("ix_detection_rules_status", "status"),
        Index("ix_detection_rules_severity", "severity"),
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
        default=lambda: f"drule_{uuid.uuid4().hex[:12]}",
        comment="Unique detection rule identifier (e.g. 'drule_fw_deny_scan')",
    )

    rule_name = Column(
        String(255),
        nullable=False,
        comment="Human-readable detection rule title",
    )

    vendor_name = Column(
        String(255),
        nullable=False,
        comment="Vendor scope this rule applies to (e.g. 'Cisco ASA', 'ANY')",
    )

    description = Column(
        Text,
        nullable=True,
        comment="Technical description of what this rule detects",
    )

    severity = Column(
        String(32),
        nullable=False,
        default="MEDIUM",
        comment="Rule severity: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    status = Column(
        String(32),
        nullable=False,
        default="DRAFT",
        comment="Lifecycle state: 'DRAFT', 'ACTIVE', 'DEPRECATED'",
    )

    version = Column(
        Integer,
        nullable=False,
        default=1,
        comment="Incremental rule version number",
    )

    mitre_tactic = Column(
        String(100),
        nullable=True,
        comment="MITRE ATT&CK tactic reference (e.g. 'TA0001: Initial Access')",
    )

    mitre_technique = Column(
        String(100),
        nullable=True,
        comment="MITRE ATT&CK technique reference (e.g. 'T1190: Exploit Public-Facing Application')",
    )

    created_by = Column(
        String(64),
        nullable=True,
        comment="User ID of the rule creator",
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

    # Relationship to field dependencies
    dependencies = relationship(
        "DetectionRuleDependency",
        back_populates="rule",
        cascade="all, delete-orphan",
        lazy="joined",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert detection rule to dictionary representation."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "vendor_name": self.vendor_name,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "version": self.version,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "created_by": self.created_by,
            "dependency_count": len(self.dependencies) if self.dependencies else 0,
            "dependencies": [d.to_dict() for d in self.dependencies] if self.dependencies else [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class DetectionRuleDependency(Base):
    """
    Canonical field dependency edge linking a detection rule to the
    canonical fields it requires for evaluation.

    Forms a DAG: DetectionRule -> canonical_field_name
    Used for impact propagation analysis when semantic policies change.
    """

    __tablename__ = "detection_rule_dependencies"
    __table_args__ = (
        Index("ix_detection_rule_deps_dep_id", "dependency_id", unique=True),
        Index("ix_detection_rule_deps_rule_id", "rule_id"),
        Index("ix_detection_rule_deps_canonical_field", "canonical_field"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    dependency_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"ddep_{uuid.uuid4().hex[:12]}",
        comment="Unique dependency edge identifier",
    )

    rule_id = Column(
        String(64),
        ForeignKey("sentinel.detection_rules.rule_id", ondelete="CASCADE"),
        nullable=False,
        comment="Foreign key to parent detection rule",
    )

    canonical_field = Column(
        String(100),
        nullable=False,
        comment="Canonical field name this rule depends on (e.g. 'action', 'severity', 'src_ip')",
    )

    dependency_type = Column(
        String(32),
        nullable=False,
        default="REQUIRED",
        comment="Dependency classification: 'REQUIRED', 'OPTIONAL', 'ENRICHMENT'",
    )

    description = Column(
        Text,
        nullable=True,
        comment="Rationale for why this field is needed by the rule",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC creation timestamp",
    )

    # Parent relationship
    rule = relationship("DetectionRule", back_populates="dependencies")

    def to_dict(self) -> Dict[str, Any]:
        """Convert dependency to dictionary representation."""
        return {
            "dependency_id": self.dependency_id,
            "rule_id": self.rule_id,
            "canonical_field": self.canonical_field,
            "dependency_type": self.dependency_type,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
