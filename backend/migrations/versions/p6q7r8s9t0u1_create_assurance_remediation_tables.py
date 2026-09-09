"""create_assurance_remediation_tables

Revision ID: p6q7r8s9t0u1
Revises: o5p6q7r8s9t0
Create Date: 2026-09-08 18:00:00.000000

Sprint 9B — Continuous Assurance Governance, Remediation & Recovery Verification.
Creates:
- sentinel.assurance_remediation_cases
- sentinel.assurance_root_cause_analyses
- sentinel.assurance_remediation_recommendations
- sentinel.assurance_remediation_plans
- sentinel.assurance_remediation_approvals
- sentinel.assurance_remediation_executions
- sentinel.assurance_recovery_verifications
- sentinel.assurance_recovery_records
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "p6q7r8s9t0u1"
down_revision: Union[str, None] = "o5p6q7r8s9t0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.assurance_remediation_cases
    op.create_table(
        "assurance_remediation_cases",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("case_number", sa.String(length=64), nullable=False),
        sa.Column("platform_assurance_evaluation_id", sa.String(length=64), nullable=True),
        sa.Column("assurance_alert_id", sa.String(length=64), nullable=True),
        sa.Column("affected_domain", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("root_cause_category", sa.String(length=64), nullable=True),
        sa.Column("root_cause_description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="MEDIUM"),
        sa.Column("priority", sa.String(length=32), nullable=False, server_default="P2"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="OPEN"),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False, server_default="SYSTEM"),
        sa.Column("assigned_to_user_id", sa.String(length=64), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deduplication_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("timeline", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_number"),
        schema="sentinel",
    )
    op.create_index(
        "ix_arc_case_number",
        "assurance_remediation_cases",
        ["case_number"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_arc_status_severity",
        "assurance_remediation_cases",
        ["status", "severity"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_arc_domain",
        "assurance_remediation_cases",
        ["affected_domain"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_arc_dedup_fp",
        "assurance_remediation_cases",
        ["deduplication_fingerprint"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_arc_created_at",
        "assurance_remediation_cases",
        ["created_at"],
        unique=False,
        schema="sentinel",
    )

    # 2. Create sentinel.assurance_root_cause_analyses
    op.create_table(
        "assurance_root_cause_analyses",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("remediation_case_id", sa.String(length=64), nullable=False),
        sa.Column("analysis_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("root_cause_category", sa.String(length=64), nullable=False),
        sa.Column("root_cause_key", sa.String(length=128), nullable=False),
        sa.Column("hypothesis", sa.Text(), nullable=False),
        sa.Column("evidence_summary", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False, server_default="MEDIUM"),
        sa.Column("analysis_status", sa.String(length=32), nullable=False, server_default="DRAFT"),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("reviewed_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["remediation_case_id"], ["sentinel.assurance_remediation_cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_arca_case_id",
        "assurance_root_cause_analyses",
        ["remediation_case_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_arca_category",
        "assurance_root_cause_analyses",
        ["root_cause_category"],
        unique=False,
        schema="sentinel",
    )

    # 3. Create sentinel.assurance_remediation_recommendations
    op.create_table(
        "assurance_remediation_recommendations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("remediation_case_id", sa.String(length=64), nullable=False),
        sa.Column("recommendation_type", sa.String(length=64), nullable=False),
        sa.Column("recommendation_title", sa.String(length=255), nullable=False),
        sa.Column("recommended_actions", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("reasoning", sa.Text(), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("requires_dual_control", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("priority", sa.String(length=32), nullable=False, server_default="P2"),
        sa.Column("deterministic_inputs", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("recommendation_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["remediation_case_id"], ["sentinel.assurance_remediation_cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_arr_case_id",
        "assurance_remediation_recommendations",
        ["remediation_case_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_arr_rec_type",
        "assurance_remediation_recommendations",
        ["recommendation_type"],
        unique=False,
        schema="sentinel",
    )

    # 4. Create sentinel.assurance_remediation_plans
    op.create_table(
        "assurance_remediation_plans",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("remediation_case_id", sa.String(length=64), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("proposed_actions", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("expected_outcome", sa.Text(), nullable=False),
        sa.Column("rollback_strategy", sa.Text(), nullable=False),
        sa.Column("estimated_risk", sa.String(length=32), nullable=False, server_default="LOW"),
        sa.Column("requires_dual_control", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
        sa.Column("proposed_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["remediation_case_id"], ["sentinel.assurance_remediation_cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_arp_case_id",
        "assurance_remediation_plans",
        ["remediation_case_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_arp_status",
        "assurance_remediation_plans",
        ["status"],
        unique=False,
        schema="sentinel",
    )

    # 5. Create sentinel.assurance_remediation_approvals
    op.create_table(
        "assurance_remediation_approvals",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("remediation_plan_id", sa.String(length=64), nullable=False),
        sa.Column("reviewer_user_id", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("review_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["remediation_plan_id"], ["sentinel.assurance_remediation_plans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_ara_plan_id",
        "assurance_remediation_approvals",
        ["remediation_plan_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_ara_reviewer",
        "assurance_remediation_approvals",
        ["reviewer_user_id"],
        unique=False,
        schema="sentinel",
    )

    # 6. Create sentinel.assurance_remediation_executions
    op.create_table(
        "assurance_remediation_executions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("remediation_case_id", sa.String(length=64), nullable=False),
        sa.Column("remediation_plan_id", sa.String(length=64), nullable=False),
        sa.Column("execution_reference", sa.String(length=128), nullable=False),
        sa.Column("external_ticket_id", sa.String(length=128), nullable=True),
        sa.Column("execution_summary", sa.Text(), nullable=False),
        sa.Column("executed_actions", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("executed_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_status", sa.String(length=32), nullable=False, server_default="COMPLETED"),
        sa.Column("execution_hash", sa.String(length=64), nullable=False),
        sa.Column("attestation", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["remediation_case_id"], ["sentinel.assurance_remediation_cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["remediation_plan_id"], ["sentinel.assurance_remediation_plans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_are_case_id",
        "assurance_remediation_executions",
        ["remediation_case_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_are_plan_id",
        "assurance_remediation_executions",
        ["remediation_plan_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_are_status",
        "assurance_remediation_executions",
        ["execution_status"],
        unique=False,
        schema="sentinel",
    )

    # 7. Create sentinel.assurance_recovery_verifications
    op.create_table(
        "assurance_recovery_verifications",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("remediation_case_id", sa.String(length=64), nullable=False),
        sa.Column("execution_id", sa.String(length=64), nullable=False),
        sa.Column("verification_status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("verification_method", sa.String(length=64), nullable=False, server_default="AUTOMATED_RE_EVALUATION"),
        sa.Column("verification_evidence", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("pre_remediation_score", sa.Float(), nullable=False),
        sa.Column("post_remediation_score", sa.Float(), nullable=False),
        sa.Column("score_delta", sa.Float(), nullable=False),
        sa.Column("domain_status_before", sa.String(length=32), nullable=False),
        sa.Column("domain_status_after", sa.String(length=32), nullable=False),
        sa.Column("verified_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("verification_reasoning", sa.Text(), nullable=False),
        sa.Column("verification_hash", sa.String(length=64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["remediation_case_id"], ["sentinel.assurance_remediation_cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["execution_id"], ["sentinel.assurance_remediation_executions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_arv_case_id",
        "assurance_recovery_verifications",
        ["remediation_case_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_arv_execution_id",
        "assurance_recovery_verifications",
        ["execution_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_arv_status",
        "assurance_recovery_verifications",
        ["verification_status"],
        unique=False,
        schema="sentinel",
    )

    # 8. Create sentinel.assurance_recovery_records
    op.create_table(
        "assurance_recovery_records",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("remediation_case_id", sa.String(length=64), nullable=False),
        sa.Column("previous_assurance_evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("new_assurance_evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("recovery_status", sa.String(length=32), nullable=False),
        sa.Column("recovery_confidence", sa.Float(), nullable=False),
        sa.Column("score_before", sa.Float(), nullable=False),
        sa.Column("score_after", sa.Float(), nullable=False),
        sa.Column("score_delta", sa.Float(), nullable=False),
        sa.Column("recovered_domains", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("remaining_degraded_domains", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("recovery_reasoning", sa.Text(), nullable=False),
        sa.Column("recovery_hash", sa.String(length=64), nullable=False),
        sa.Column("confirmed_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["remediation_case_id"], ["sentinel.assurance_remediation_cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_arrd_case_id",
        "assurance_recovery_records",
        ["remediation_case_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_arrd_status",
        "assurance_recovery_records",
        ["recovery_status"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_arrd_created_at",
        "assurance_recovery_records",
        ["created_at"],
        unique=False,
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_table("assurance_recovery_records", schema="sentinel")
    op.drop_table("assurance_recovery_verifications", schema="sentinel")
    op.drop_table("assurance_remediation_executions", schema="sentinel")
    op.drop_table("assurance_remediation_approvals", schema="sentinel")
    op.drop_table("assurance_remediation_plans", schema="sentinel")
    op.drop_table("assurance_remediation_recommendations", schema="sentinel")
    op.drop_table("assurance_root_cause_analyses", schema="sentinel")
    op.drop_table("assurance_remediation_cases", schema="sentinel")
