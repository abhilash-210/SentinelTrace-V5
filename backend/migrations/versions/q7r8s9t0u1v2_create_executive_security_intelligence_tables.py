"""create_executive_security_intelligence_tables

Revision ID: q7r8s9t0u1v2
Revises: p6q7r8s9t0u1
Create Date: 2026-09-08 20:00:00.000000

Sprint 10A — Unified Security Intelligence & Executive Risk Posture Command Center.
Creates:
- sentinel.executive_security_posture_evaluations
- sentinel.executive_posture_domain_scores
- sentinel.executive_risk_drivers
- sentinel.executive_posture_trend_snapshots
- sentinel.executive_security_insights
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "q7r8s9t0u1v2"
down_revision: Union[str, None] = "p6q7r8s9t0u1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.executive_security_posture_evaluations
    op.create_table(
        "executive_security_posture_evaluations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("evaluation_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("overall_posture_status", sa.String(length=32), nullable=False),
        sa.Column("overall_security_score", sa.Float(), nullable=False),
        sa.Column("executive_risk_score", sa.Float(), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("critical_driver_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high_driver_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium_driver_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_critical_incidents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_high_incidents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unresolved_assurance_alerts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active_detection_trust_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_semantic_drift_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_remediation_cases", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cryptographic_integrity_status", sa.String(length=32), nullable=False, server_default="VERIFIED"),
        sa.Column("previous_evaluation_id", sa.String(length=64), nullable=True),
        sa.Column("score_delta", sa.Float(), nullable=True),
        sa.Column("posture_change", sa.String(length=64), nullable=True),
        sa.Column("evaluation_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("canonical_payload", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("evaluation_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evaluation_id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_espe_status_eval_ts",
        "executive_security_posture_evaluations",
        ["overall_posture_status", "evaluation_timestamp"],
        schema="sentinel",
    )
    op.create_index(
        "ix_espe_eval_hash",
        "executive_security_posture_evaluations",
        ["evaluation_hash"],
        schema="sentinel",
    )
    op.create_index(
        "ix_espe_eval_ts",
        "executive_security_posture_evaluations",
        ["evaluation_timestamp"],
        schema="sentinel",
    )
    op.create_index(
        "ix_espe_evaluation_id",
        "executive_security_posture_evaluations",
        ["evaluation_id"],
        unique=True,
        schema="sentinel",
    )

    # 2. Create sentinel.executive_posture_domain_scores
    op.create_table(
        "executive_posture_domain_scores",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("posture_evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("domain_name", sa.String(length=64), nullable=False),
        sa.Column("base_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("deduction_total", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("final_score", sa.Float(), nullable=False),
        sa.Column("risk_weight", sa.Float(), nullable=False),
        sa.Column("weighted_contribution", sa.Float(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("critical_flag", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("unknown_flag", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("primary_driver", sa.String(length=255), nullable=False, server_default="NORMAL_OPERATIONS"),
        sa.Column("explanation", sa.Text(), nullable=False, server_default=""),
        sa.Column("canonical_payload", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["posture_evaluation_id"],
            ["sentinel.executive_security_posture_evaluations.evaluation_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_epds_eval_domain",
        "executive_posture_domain_scores",
        ["posture_evaluation_id", "domain_name"],
        schema="sentinel",
    )
    op.create_index(
        "ix_epds_status",
        "executive_posture_domain_scores",
        ["status"],
        schema="sentinel",
    )

    # 3. Create sentinel.executive_risk_drivers
    op.create_table(
        "executive_risk_drivers",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("driver_id", sa.String(length=64), nullable=False),
        sa.Column("posture_evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("driver_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("risk_points", sa.Float(), nullable=False),
        sa.Column("domain", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("source_entity_type", sa.String(length=64), nullable=False),
        sa.Column("source_entity_id", sa.String(length=128), nullable=False),
        sa.Column("source_reference", sa.String(length=255), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("resolved", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["posture_evaluation_id"],
            ["sentinel.executive_security_posture_evaluations.evaluation_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("driver_id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_erd_eval_rank",
        "executive_risk_drivers",
        ["posture_evaluation_id", "rank"],
        schema="sentinel",
    )
    op.create_index(
        "ix_erd_severity_active",
        "executive_risk_drivers",
        ["severity", "active"],
        schema="sentinel",
    )
    op.create_index(
        "ix_erd_driver_type",
        "executive_risk_drivers",
        ["driver_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_erd_driver_id",
        "executive_risk_drivers",
        ["driver_id"],
        unique=True,
        schema="sentinel",
    )

    # 4. Create sentinel.executive_posture_trend_snapshots
    op.create_table(
        "executive_posture_trend_snapshots",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("snapshot_id", sa.String(length=64), nullable=False),
        sa.Column("posture_evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("overall_security_score", sa.Float(), nullable=False),
        sa.Column("executive_risk_score", sa.Float(), nullable=False),
        sa.Column("posture_status", sa.String(length=32), nullable=False),
        sa.Column("critical_driver_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_incident_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assurance_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("detection_trust_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("cryptographic_status", sa.String(length=32), nullable=False, server_default="VERIFIED"),
        sa.Column("score_delta", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["posture_evaluation_id"],
            ["sentinel.executive_security_posture_evaluations.evaluation_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("snapshot_id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_epts_timestamp",
        "executive_posture_trend_snapshots",
        ["timestamp"],
        schema="sentinel",
    )
    op.create_index(
        "ix_epts_posture_status",
        "executive_posture_trend_snapshots",
        ["posture_status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_epts_snapshot_id",
        "executive_posture_trend_snapshots",
        ["snapshot_id"],
        unique=True,
        schema="sentinel",
    )

    # 5. Create sentinel.executive_security_insights
    op.create_table(
        "executive_security_insights",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("insight_id", sa.String(length=64), nullable=False),
        sa.Column("posture_evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("insight_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("supporting_metrics", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("recommended_attention", sa.Text(), nullable=False),
        sa.Column("source_domains", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("canonical_payload", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("insight_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["posture_evaluation_id"],
            ["sentinel.executive_security_posture_evaluations.evaluation_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("insight_id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_esi_type_sev",
        "executive_security_insights",
        ["insight_type", "severity"],
        schema="sentinel",
    )
    op.create_index(
        "ix_esi_eval_id",
        "executive_security_insights",
        ["posture_evaluation_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_esi_insight_id",
        "executive_security_insights",
        ["insight_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_esi_insight_hash",
        "executive_security_insights",
        ["insight_hash"],
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_table("executive_security_insights", schema="sentinel")
    op.drop_table("executive_posture_trend_snapshots", schema="sentinel")
    op.drop_table("executive_risk_drivers", schema="sentinel")
    op.drop_table("executive_posture_domain_scores", schema="sentinel")
    op.drop_table("executive_security_posture_evaluations", schema="sentinel")
