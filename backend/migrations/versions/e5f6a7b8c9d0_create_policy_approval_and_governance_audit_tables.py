"""create_policy_approval_and_governance_audit_tables

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-09-06 23:00:00.000000

Sprint 4B — Dual-Control Approval & Policy Governance Workflow.
Creates:
- sentinel.policy_approval_requests: Maker-checker approval request lifecycle
- sentinel.governance_audit_log: Append-only immutable governance audit trail
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.policy_approval_requests table
    op.create_table(
        "policy_approval_requests",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("approval_id", sa.String(length=64), nullable=False),
        sa.Column("policy_id", sa.String(length=64), nullable=False),
        sa.Column("requested_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="PENDING", nullable=False),
        sa.Column("reviewed_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["sentinel.semantic_policies.policy_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("approval_id"),
        schema="sentinel",
    )
    op.create_index("ix_policy_approvals_approval_id", "policy_approval_requests", ["approval_id"], unique=True, schema="sentinel")
    op.create_index("ix_policy_approvals_policy_id", "policy_approval_requests", ["policy_id"], unique=False, schema="sentinel")
    op.create_index("ix_policy_approvals_status", "policy_approval_requests", ["status"], unique=False, schema="sentinel")
    op.create_index("ix_policy_approvals_requested_by", "policy_approval_requests", ["requested_by_user_id"], unique=False, schema="sentinel")

    # 2. Create sentinel.governance_audit_log table
    op.create_table(
        "governance_audit_log",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("audit_id", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id", sa.String(length=64), nullable=False),
        sa.Column("actor_username", sa.String(length=64), nullable=False),
        sa.Column("actor_role", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=64), server_default="SEMANTIC_POLICY", nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=False),
        sa.Column("previous_state", sa.String(length=64), nullable=True),
        sa.Column("new_state", sa.String(length=64), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("metadata_json", JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("audit_id"),
        schema="sentinel",
    )
    op.create_index("ix_gov_audit_audit_id", "governance_audit_log", ["audit_id"], unique=True, schema="sentinel")
    op.create_index("ix_gov_audit_resource", "governance_audit_log", ["resource_type", "resource_id"], unique=False, schema="sentinel")
    op.create_index("ix_gov_audit_actor", "governance_audit_log", ["actor_user_id"], unique=False, schema="sentinel")
    op.create_index("ix_gov_audit_action", "governance_audit_log", ["action"], unique=False, schema="sentinel")
    op.create_index("ix_gov_audit_created_at", "governance_audit_log", ["created_at"], unique=False, schema="sentinel")


def downgrade() -> None:
    op.drop_index("ix_gov_audit_created_at", table_name="governance_audit_log", schema="sentinel")
    op.drop_index("ix_gov_audit_action", table_name="governance_audit_log", schema="sentinel")
    op.drop_index("ix_gov_audit_actor", table_name="governance_audit_log", schema="sentinel")
    op.drop_index("ix_gov_audit_resource", table_name="governance_audit_log", schema="sentinel")
    op.drop_index("ix_gov_audit_audit_id", table_name="governance_audit_log", schema="sentinel")
    op.drop_table("governance_audit_log", schema="sentinel")

    op.drop_index("ix_policy_approvals_requested_by", table_name="policy_approval_requests", schema="sentinel")
    op.drop_index("ix_policy_approvals_status", table_name="policy_approval_requests", schema="sentinel")
    op.drop_index("ix_policy_approvals_policy_id", table_name="policy_approval_requests", schema="sentinel")
    op.drop_index("ix_policy_approvals_approval_id", table_name="policy_approval_requests", schema="sentinel")
    op.drop_table("policy_approval_requests", schema="sentinel")
