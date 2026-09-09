"""create_security_assurance_tables

Revision ID: o5p6q7r8s9t0
Revises: n4o5p6q7r8s9
Create Date: 2026-09-08 14:00:00.000000

Sprint 9A — Continuous Security Assurance & Platform Health Intelligence.
Creates:
- sentinel.assurance_domain_evaluations: Immutable point-in-time domain evaluation snapshots
- sentinel.platform_assurance_evaluations: Platform-wide composite assurance evaluations
- sentinel.assurance_alerts: Actionable assurance degradation and trust regression alerts
- sentinel.assurance_metric_definitions: Deterministic metric catalog and threshold configuration
- sentinel.assurance_trend_snapshots: Time-series trend snapshots for historical analytics
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "o5p6q7r8s9t0"
down_revision: Union[str, None] = "n4o5p6q7r8s9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.assurance_domain_evaluations
    op.create_table(
        "assurance_domain_evaluations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("domain_name", sa.String(length=64), nullable=False),
        sa.Column("evaluation_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("metric_snapshot", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("deductions", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False, server_default="LOW"),
        sa.Column("evaluation_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_ade_domain_eval_ts",
        "assurance_domain_evaluations",
        ["domain_name", "evaluation_timestamp"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_ade_status_eval_ts",
        "assurance_domain_evaluations",
        ["status", "evaluation_timestamp"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_ade_evaluation_hash",
        "assurance_domain_evaluations",
        ["evaluation_hash"],
        unique=False,
        schema="sentinel",
    )

    # 2. Create sentinel.platform_assurance_evaluations
    op.create_table(
        "platform_assurance_evaluations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("evaluation_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("overall_score", sa.Float(), nullable=False),
        sa.Column("overall_status", sa.String(length=32), nullable=False),
        sa.Column("evidence_score", sa.Float(), nullable=False),
        sa.Column("normalization_score", sa.Float(), nullable=False),
        sa.Column("semantic_score", sa.Float(), nullable=False),
        sa.Column("detection_score", sa.Float(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("incident_response_score", sa.Float(), nullable=False),
        sa.Column("cryptographic_score", sa.Float(), nullable=False),
        sa.Column("domain_weights", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("score_breakdown", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("critical_conditions", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("evaluation_hash", sa.String(length=64), nullable=False),
        sa.Column("previous_evaluation_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_pae_status_eval_ts",
        "platform_assurance_evaluations",
        ["overall_status", "evaluation_timestamp"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_pae_eval_hash",
        "platform_assurance_evaluations",
        ["evaluation_hash"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_pae_eval_ts",
        "platform_assurance_evaluations",
        ["evaluation_timestamp"],
        unique=False,
        schema="sentinel",
    )

    # 3. Create sentinel.assurance_alerts
    op.create_table(
        "assurance_alerts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("alert_type", sa.String(length=64), nullable=False),
        sa.Column("domain_name", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="OPEN"),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source_evaluation_id", sa.String(length=64), nullable=True),
        sa.Column("previous_score", sa.Float(), nullable=True),
        sa.Column("current_score", sa.Float(), nullable=False),
        sa.Column("score_delta", sa.Float(), nullable=True),
        sa.Column("deduplication_key", sa.String(length=64), nullable=False),
        sa.Column("first_detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(length=64), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_aa_status_severity",
        "assurance_alerts",
        ["status", "severity"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_aa_dedup_key",
        "assurance_alerts",
        ["deduplication_key"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_aa_domain",
        "assurance_alerts",
        ["domain_name"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_aa_alert_type",
        "assurance_alerts",
        ["alert_type"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_aa_created_at",
        "assurance_alerts",
        ["created_at"],
        unique=False,
        schema="sentinel",
    )

    # 4. Create sentinel.assurance_metric_definitions
    op.create_table(
        "assurance_metric_definitions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("metric_key", sa.String(length=64), nullable=False),
        sa.Column("domain_name", sa.String(length=64), nullable=False),
        sa.Column("metric_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("weight", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("healthy_threshold", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("degraded_threshold", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("at_risk_threshold", sa.Float(), nullable=False, server_default="5.0"),
        sa.Column("critical_threshold", sa.Float(), nullable=False, server_default="10.0"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_amd_metric_key",
        "assurance_metric_definitions",
        ["metric_key"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_amd_domain",
        "assurance_metric_definitions",
        ["domain_name"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_amd_enabled",
        "assurance_metric_definitions",
        ["enabled"],
        unique=False,
        schema="sentinel",
    )

    # 5. Create sentinel.assurance_trend_snapshots
    op.create_table(
        "assurance_trend_snapshots",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("platform_evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("snapshot_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("overall_score", sa.Float(), nullable=False),
        sa.Column("overall_status", sa.String(length=32), nullable=False),
        sa.Column("domain_scores", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("score_delta", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_ats_snapshot_ts",
        "assurance_trend_snapshots",
        ["snapshot_timestamp"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_ats_platform_eval_id",
        "assurance_trend_snapshots",
        ["platform_evaluation_id"],
        unique=False,
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_table("assurance_trend_snapshots", schema="sentinel")
    op.drop_table("assurance_metric_definitions", schema="sentinel")
    op.drop_table("assurance_alerts", schema="sentinel")
    op.drop_table("platform_assurance_evaluations", schema="sentinel")
    op.drop_table("assurance_domain_evaluations", schema="sentinel")
