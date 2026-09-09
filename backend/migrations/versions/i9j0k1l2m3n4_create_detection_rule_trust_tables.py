"""create_detection_rule_trust_tables

Revision ID: i9j0k1l2m3n4
Revises: h8i9j0k1l2m3
Create Date: 2026-09-07 01:00:00.000000

Sprint 6B — Detection Rule Trust Evaluation & Semantic Drift Binding.
Creates:
- sentinel.detection_rule_trust_evaluations: Immutable point-in-time rule trust evaluation records
- sentinel.detection_trust_alerts: Trust degradation and risk alerts
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "i9j0k1l2m3n4"
down_revision: Union[str, None] = "h8i9j0k1l2m3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.detection_rule_trust_evaluations table
    op.create_table(
        "detection_rule_trust_evaluations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("normalized_event_id", sa.String(length=64), nullable=True),
        sa.Column("interpretation_id", sa.String(length=64), nullable=True),
        sa.Column("drift_alert_id", sa.String(length=64), nullable=True),
        sa.Column("canonical_field", sa.String(length=128), nullable=False),
        sa.Column("trust_status", sa.String(length=32), nullable=False),
        sa.Column("trust_score", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column(
            "evaluation_reasons",
            JSONB().with_variant(JSON(), "sqlite"),
            nullable=False,
        ),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("evaluation_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["sentinel.detection_rules.rule_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_eval_evaluation_id",
        "detection_rule_trust_evaluations",
        ["evaluation_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_eval_rule_id",
        "detection_rule_trust_evaluations",
        ["rule_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_eval_normalized_event_id",
        "detection_rule_trust_evaluations",
        ["normalized_event_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_eval_interpretation_id",
        "detection_rule_trust_evaluations",
        ["interpretation_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_eval_drift_alert_id",
        "detection_rule_trust_evaluations",
        ["drift_alert_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_eval_canonical_field",
        "detection_rule_trust_evaluations",
        ["canonical_field"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_eval_trust_status",
        "detection_rule_trust_evaluations",
        ["trust_status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_eval_risk_level",
        "detection_rule_trust_evaluations",
        ["risk_level"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_eval_created_at",
        "detection_rule_trust_evaluations",
        ["created_at"],
        schema="sentinel",
    )

    # 2. Create sentinel.detection_trust_alerts table
    op.create_table(
        "detection_trust_alerts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("drift_alert_id", sa.String(length=64), nullable=True),
        sa.Column("alert_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="OPEN"),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("affected_field", sa.String(length=128), nullable=False),
        sa.Column("trust_status", sa.String(length=32), nullable=False),
        sa.Column("trust_score", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["sentinel.detection_rules.rule_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evaluation_id"],
            ["sentinel.detection_rule_trust_evaluations.evaluation_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_alerts_alert_id",
        "detection_trust_alerts",
        ["alert_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_alerts_rule_id",
        "detection_trust_alerts",
        ["rule_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_alerts_eval_id",
        "detection_trust_alerts",
        ["evaluation_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_alerts_drift_alert_id",
        "detection_trust_alerts",
        ["drift_alert_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_alerts_severity",
        "detection_trust_alerts",
        ["severity"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_alerts_status",
        "detection_trust_alerts",
        ["status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_alerts_alert_type",
        "detection_trust_alerts",
        ["alert_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_trust_alerts_created_at",
        "detection_trust_alerts",
        ["created_at"],
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_table("detection_trust_alerts", schema="sentinel")
    op.drop_table("detection_rule_trust_evaluations", schema="sentinel")
