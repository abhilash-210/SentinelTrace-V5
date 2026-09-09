"""create_detection_execution_tables

Revision ID: k1l2m3n4o5p6
Revises: j0k1l2m3n4o5
Create Date: 2026-09-07 18:00:00.000000

Sprint 7A — Real-Time Detection Rule Execution Engine.
Creates:
- sentinel.detection_executions: Deterministic execution records for ACTIVE detection rules evaluated against normalized events
- sentinel.detection_condition_results: Granular condition-level explainability records
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "k1l2m3n4o5p6"
down_revision: Union[str, None] = "j0k1l2m3n4o5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.detection_executions
    op.create_table(
        "detection_executions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("execution_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version_number", sa.Integer(), nullable=False),
        sa.Column("normalized_event_id", sa.String(length=64), nullable=False),
        sa.Column("original_event_id", sa.String(length=64), nullable=False),
        sa.Column("execution_status", sa.String(length=32), nullable=False),
        sa.Column("matched", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("conditions_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("conditions_matched", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("conditions_missing", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("execution_fingerprint", sa.String(length=64), nullable=False),
        sa.Column(
            "execution_details",
            JSONB().with_variant(JSON(), "sqlite"),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("execution_explanation", sa.Text(), nullable=True),
        sa.Column(
            "executed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("execution_engine_version", sa.String(length=32), nullable=False, server_default="v5.7.0"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("execution_id", name="uq_detection_executions_execution_id"),
        sa.UniqueConstraint("execution_fingerprint", name="uq_detection_executions_fingerprint"),
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_executions_execution_id",
        "detection_executions",
        ["execution_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_executions_rule_id",
        "detection_executions",
        ["rule_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_executions_rule_version_id",
        "detection_executions",
        ["rule_version_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_executions_norm_event_id",
        "detection_executions",
        ["normalized_event_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_executions_status",
        "detection_executions",
        ["execution_status"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_executions_executed_at",
        "detection_executions",
        ["executed_at"],
        unique=False,
        schema="sentinel",
    )

    # 2. Create sentinel.detection_condition_results
    op.create_table(
        "detection_condition_results",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("execution_id", sa.String(length=64), nullable=False),
        sa.Column("condition_index", sa.Integer(), nullable=False),
        sa.Column("canonical_field", sa.String(length=100), nullable=False),
        sa.Column("comparison_operator", sa.String(length=32), nullable=False),
        sa.Column(
            "expected_value",
            JSONB().with_variant(JSON(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "observed_value",
            JSONB().with_variant(JSON(), "sqlite"),
            nullable=True,
        ),
        sa.Column("field_resolved", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("condition_result", sa.String(length=32), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["execution_id"],
            ["sentinel.detection_executions.execution_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_cond_results_execution_id",
        "detection_condition_results",
        ["execution_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_cond_results_field",
        "detection_condition_results",
        ["canonical_field"],
        unique=False,
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_index("ix_detection_cond_results_field", table_name="detection_condition_results", schema="sentinel")
    op.drop_index("ix_detection_cond_results_execution_id", table_name="detection_condition_results", schema="sentinel")
    op.drop_table("detection_condition_results", schema="sentinel")

    op.drop_index("ix_detection_executions_executed_at", table_name="detection_executions", schema="sentinel")
    op.drop_index("ix_detection_executions_status", table_name="detection_executions", schema="sentinel")
    op.drop_index("ix_detection_executions_norm_event_id", table_name="detection_executions", schema="sentinel")
    op.drop_index("ix_detection_executions_rule_version_id", table_name="detection_executions", schema="sentinel")
    op.drop_index("ix_detection_executions_rule_id", table_name="detection_executions", schema="sentinel")
    op.drop_index("ix_detection_executions_execution_id", table_name="detection_executions", schema="sentinel")
    op.drop_table("detection_executions", schema="sentinel")
