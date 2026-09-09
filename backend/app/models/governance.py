"""
models/governance.py
--------------------
SQLAlchemy ORM models for Dual-Control Policy Approval and Governance Audit Trails.

Sprint 4B — Dual-Control Approval & Policy Governance Workflow.
Schema: sentinel.policy_approval_requests and sentinel.governance_audit_log
"""

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, Optional

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    Index,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PolicyApprovalRequest(Base):
    """
    Tracks formal maker-checker dual-control approval requests for semantic policies.
    """

    __tablename__ = "policy_approval_requests"
    __table_args__ = (
        Index("ix_policy_approvals_status", "status"),
        Index("ix_policy_approvals_policy_id", "policy_id"),
        Index("ix_policy_approvals_requested_by", "requested_by_user_id"),
        {"schema": "sentinel"},
    )

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    approval_id = Column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: f"approval_{uuid.uuid4().hex[:12]}",
        doc="Unique identifier for the approval ticket (e.g. approval_...)",
    )
    policy_id = Column(
        String(64),
        ForeignKey("sentinel.semantic_policies.policy_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Target semantic policy undergoing review",
    )
    requested_by_user_id = Column(
        String(64),
        nullable=False,
        doc="User ID of author who submitted policy for review",
    )
    requested_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        doc="Timestamp of submission",
    )
    status = Column(
        String(32),
        nullable=False,
        default="PENDING",
        doc="Approval lifecycle: PENDING, APPROVED, REJECTED, CANCELLED",
    )
    reviewed_by_user_id = Column(
        String(64),
        nullable=True,
        doc="User ID of reviewer who approved or rejected the policy",
    )
    reviewed_at = Column(
        DateTime(timezone=True),
        nullable=True,
        doc="Timestamp when decision was rendered",
    )
    review_comment = Column(
        Text,
        nullable=True,
        doc="Review rationale or rejection notes",
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
        onupdate=utcnow,
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "approval_id": self.approval_id,
            "policy_id": self.policy_id,
            "requested_by_user_id": self.requested_by_user_id,
            "requested_at": self.requested_at.isoformat() if self.requested_at else None,
            "status": self.status,
            "reviewed_by_user_id": self.reviewed_by_user_id,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "review_comment": self.review_comment,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class GovernanceAuditLog(Base):
    """
    Append-only chronological audit log of all semantic policy governance lifecycle events.
    """

    __tablename__ = "governance_audit_log"
    __table_args__ = (
        Index("ix_gov_audit_resource", "resource_type", "resource_id"),
        Index("ix_gov_audit_actor", "actor_user_id"),
        Index("ix_gov_audit_action", "action"),
        Index("ix_gov_audit_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    audit_id = Column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: f"audit_{uuid.uuid4().hex[:12]}",
        doc="Unique audit event record ID",
    )
    actor_user_id = Column(
        String(64),
        nullable=False,
        doc="Identity of user who performed the governance action",
    )
    actor_username = Column(
        String(64),
        nullable=False,
        doc="Username handle of actor",
    )
    actor_role = Column(
        String(32),
        nullable=False,
        doc="Role of actor at transaction time",
    )
    action = Column(
        String(64),
        nullable=False,
        doc="Governance event (POLICY_CREATED, POLICY_SUBMITTED, POLICY_APPROVED, POLICY_REJECTED, POLICY_ACTIVATED, POLICY_SUPERSEDED, etc.)",
    )
    resource_type = Column(
        String(64),
        nullable=False,
        default="SEMANTIC_POLICY",
        doc="Target resource type",
    )
    resource_id = Column(
        String(64),
        nullable=False,
        doc="ID of affected entity (e.g. policy_id or approval_id)",
    )
    previous_state = Column(
        String(64),
        nullable=True,
        doc="State prior to transition",
    )
    new_state = Column(
        String(64),
        nullable=True,
        doc="State following transition",
    )
    reason = Column(
        Text,
        nullable=True,
        doc="Operational notes or review comments",
    )
    metadata_json = Column(
        JSON,
        nullable=True,
        doc="Extensible contextual metadata snapshot",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        index=True,
        doc="Exact UTC timestamp of audit entry",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "audit_id": self.audit_id,
            "actor_user_id": self.actor_user_id,
            "actor_username": self.actor_username,
            "actor_role": self.actor_role,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "reason": self.reason,
            "metadata": self.metadata_json or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
