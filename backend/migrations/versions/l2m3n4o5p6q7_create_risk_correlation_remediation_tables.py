"""create_risk_correlation_remediation_tables

Revision ID: l2m3n4o5p6q7
Revises: k1l2m3n4o5p6
Create Date: 2026-09-08 09:30:00.000000

Sprint 7B — Security Posture Risk Correlation, Prioritized Remediation & Executive Risk Intelligence.
Creates:
- sentinel.risk_correlations: Deterministic correlation records for aggregated security findings and risk chains
- sentinel.risk_correlation_members: Association graph members linking signals, rules, fields, and events
- sentinel.remediation_candidates: Actionable, evidence-backed remediation candidates with mathematical priority scoring
- sentinel.remediation_actions: Auditable log of remediation lifecycle transitions, simulations, and reviews
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "l2m3n4o5p6q7"
down_revision: Union[str, None] = "k1l2m3n4o5p6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.risk_correlations
    op.create_table(
        "risk_correlations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("correlation_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("risk_cluster_key", sa.String(length=128), nullable=True),
        sa.Column("affected_signal_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("affected_rule_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("affected_field_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("root_cause_candidates", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_risk_corr_correlation_id",
        "risk_correlations",
        ["correlation_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_risk_corr_type",
        "risk_correlations",
        ["correlation_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_risk_corr_severity",
        "risk_correlations",
        ["severity"],
        schema="sentinel",
    )
    op.create_index(
        "ix_risk_corr_status",
        "risk_correlations",
        ["status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_risk_corr_cluster_key",
        "risk_correlations",
        ["risk_cluster_key"],
        schema="sentinel",
    )
    op.create_index(
        "ix_risk_corr_created_at",
        "risk_correlations",
        ["created_at"],
        schema="sentinel",
    )

    # 2. Create sentinel.risk_correlation_members
    op.create_table(
        "risk_correlation_members",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("member_type", sa.String(length=64), nullable=False),
        sa.Column("member_id", sa.String(length=128), nullable=False),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["correlation_id"],
            ["sentinel.risk_correlations.correlation_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_risk_member_corr_id",
        "risk_correlation_members",
        ["correlation_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_risk_member_type_id",
        "risk_correlation_members",
        ["member_type", "member_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_risk_member_rel_type",
        "risk_correlation_members",
        ["relationship_type"],
        schema="sentinel",
    )

    # 3. Create sentinel.remediation_candidates
    op.create_table(
        "remediation_candidates",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("remediation_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation_type", sa.String(length=64), nullable=False),
        sa.Column("priority_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("priority_classification", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="GENERATED"),
        sa.Column("expected_risk_reduction", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("simulation_confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("related_posture_snapshot_id", sa.String(length=64), nullable=True),
        sa.Column("related_correlation_id", sa.String(length=64), nullable=True),
        sa.Column("affected_fields", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("affected_rules", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("affected_policies", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("root_cause_candidates", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("deterministic_reasoning", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False, server_default="SYSTEM_DETERMINISTIC_ENGINE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["related_correlation_id"],
            ["sentinel.risk_correlations.correlation_id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_remediation_remediation_id",
        "remediation_candidates",
        ["remediation_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_remediation_type",
        "remediation_candidates",
        ["remediation_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_remediation_priority_score",
        "remediation_candidates",
        ["priority_score"],
        schema="sentinel",
    )
    op.create_index(
        "ix_remediation_priority_class",
        "remediation_candidates",
        ["priority_classification"],
        schema="sentinel",
    )
    op.create_index(
        "ix_remediation_severity",
        "remediation_candidates",
        ["severity"],
        schema="sentinel",
    )
    op.create_index(
        "ix_remediation_status",
        "remediation_candidates",
        ["status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_remediation_corr_id",
        "remediation_candidates",
        ["related_correlation_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_remediation_created_at",
        "remediation_candidates",
        ["created_at"],
        schema="sentinel",
    )

    # 4. Create sentinel.remediation_actions
    op.create_table(
        "remediation_actions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("action_id", sa.String(length=64), nullable=False),
        sa.Column("remediation_id", sa.String(length=64), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("from_status", sa.String(length=32), nullable=True),
        sa.Column("to_status", sa.String(length=32), nullable=False),
        sa.Column("performed_by", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["remediation_id"],
            ["sentinel.remediation_candidates.remediation_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_rem_action_action_id",
        "remediation_actions",
        ["action_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_rem_action_remediation_id",
        "remediation_actions",
        ["remediation_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_rem_action_performed_by",
        "remediation_actions",
        ["performed_by"],
        schema="sentinel",
    )
    op.create_index(
        "ix_rem_action_created_at",
        "remediation_actions",
        ["created_at"],
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_table("remediation_actions", schema="sentinel")
    op.drop_table("remediation_candidates", schema="sentinel")
    op.drop_table("risk_correlation_members", schema="sentinel")
    op.drop_table("risk_correlations", schema="sentinel")
