"""create_security_scenario_tables

Revision ID: r8s9t0u1v2w3
Revises: q7r8s9t0u1v2
Create Date: 2026-09-08 22:00:00.000000

Sprint 10B — End-to-End Security Scenario Orchestration, Demonstration Validation & Cross-Domain Evidence Replay.
Creates:
- sentinel.security_scenarios
- sentinel.security_scenario_versions
- sentinel.scenario_executions
- sentinel.scenario_stage_executions
- sentinel.scenario_artifact_bindings
- sentinel.scenario_verification_results
- sentinel.scenario_executive_impacts
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "r8s9t0u1v2w3"
down_revision: Union[str, None] = "q7r8s9t0u1v2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.security_scenarios
    op.create_table(
        "security_scenarios",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("scenario_key", sa.String(length=128), nullable=False),
        sa.Column("scenario_name", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="HIGH"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
        sa.Column("current_version_id", sa.String(length=64), nullable=True),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scenario_key", name="uq_security_scenarios_key"),
        schema="sentinel",
    )
    op.create_index(
        "ix_security_scenarios_key",
        "security_scenarios",
        ["scenario_key"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_security_scenarios_category",
        "security_scenarios",
        ["category"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_security_scenarios_status",
        "security_scenarios",
        ["status"],
        unique=False,
        schema="sentinel",
    )

    # 2. Create sentinel.security_scenario_versions
    op.create_table(
        "security_scenario_versions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("scenario_id", sa.String(length=64), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("scenario_definition_json", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("expected_stage_sequence_json", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("expected_outcomes_json", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("deterministic_seed", sa.String(length=128), nullable=False),
        sa.Column("definition_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["scenario_id"],
            ["sentinel.security_scenarios.id"],
            name="fk_scenario_versions_scenario_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("scenario_id", "version_number", name="uq_scenario_version_number"),
        schema="sentinel",
    )
    op.create_index(
        "ix_scenario_versions_scenario_id",
        "security_scenario_versions",
        ["scenario_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_scenario_versions_status",
        "security_scenario_versions",
        ["status"],
        unique=False,
        schema="sentinel",
    )

    # 3. Create sentinel.scenario_executions
    op.create_table(
        "scenario_executions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("execution_number", sa.String(length=64), nullable=False),
        sa.Column("scenario_id", sa.String(length=64), nullable=False),
        sa.Column("scenario_version_id", sa.String(length=64), nullable=False),
        sa.Column("execution_mode", sa.String(length=32), nullable=False, server_default="CONTROLLED_DEMO"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="CREATED"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("initiated_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("deterministic_execution_seed", sa.String(length=128), nullable=False),
        sa.Column("execution_hash", sa.String(length=64), nullable=False),
        sa.Column("verification_status", sa.String(length=32), nullable=False, server_default="UNVERIFIED"),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["scenario_id"],
            ["sentinel.security_scenarios.id"],
            name="fk_scenario_executions_scenario_id",
        ),
        sa.ForeignKeyConstraint(
            ["scenario_version_id"],
            ["sentinel.security_scenario_versions.id"],
            name="fk_scenario_executions_version_id",
        ),
        sa.UniqueConstraint("execution_number", name="uq_scenario_executions_number"),
        schema="sentinel",
    )
    op.create_index(
        "ix_scenario_executions_number",
        "scenario_executions",
        ["execution_number"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_scenario_executions_scenario_id",
        "scenario_executions",
        ["scenario_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_scenario_executions_status",
        "scenario_executions",
        ["status"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_scenario_executions_mode",
        "scenario_executions",
        ["execution_mode"],
        unique=False,
        schema="sentinel",
    )

    # 4. Create sentinel.scenario_stage_executions
    op.create_table(
        "scenario_stage_executions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("scenario_execution_id", sa.String(length=64), nullable=False),
        sa.Column("stage_number", sa.Integer(), nullable=False),
        sa.Column("stage_key", sa.String(length=64), nullable=False),
        sa.Column("stage_name", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("input_reference_json", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("output_reference_json", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("verification_result", sa.String(length=32), nullable=False, server_default="UNVERIFIED"),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("execution_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["scenario_execution_id"],
            ["sentinel.scenario_executions.id"],
            name="fk_stage_executions_scenario_exec_id",
            ondelete="CASCADE",
        ),
        schema="sentinel",
    )
    op.create_index(
        "ix_stage_executions_scenario_exec",
        "scenario_stage_executions",
        ["scenario_execution_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_stage_executions_stage_num",
        "scenario_stage_executions",
        ["scenario_execution_id", "stage_number"],
        unique=False,
        schema="sentinel",
    )

    # 5. Create sentinel.scenario_artifact_bindings
    op.create_table(
        "scenario_artifact_bindings",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("scenario_execution_id", sa.String(length=64), nullable=False),
        sa.Column("stage_execution_id", sa.String(length=64), nullable=False),
        sa.Column("artifact_domain", sa.String(length=64), nullable=False),
        sa.Column("artifact_type", sa.String(length=64), nullable=False),
        sa.Column("artifact_id", sa.String(length=128), nullable=False),
        sa.Column("artifact_hash", sa.String(length=64), nullable=False),
        sa.Column("artifact_reference_json", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("binding_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["scenario_execution_id"],
            ["sentinel.scenario_executions.id"],
            name="fk_artifact_bindings_exec_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["stage_execution_id"],
            ["sentinel.scenario_stage_executions.id"],
            name="fk_artifact_bindings_stage_id",
            ondelete="CASCADE",
        ),
        schema="sentinel",
    )
    op.create_index(
        "ix_artifact_bindings_exec_id",
        "scenario_artifact_bindings",
        ["scenario_execution_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_artifact_bindings_stage_id",
        "scenario_artifact_bindings",
        ["stage_execution_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_artifact_bindings_artifact_id",
        "scenario_artifact_bindings",
        ["artifact_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_artifact_bindings_domain",
        "scenario_artifact_bindings",
        ["artifact_domain"],
        unique=False,
        schema="sentinel",
    )

    # 6. Create sentinel.scenario_verification_results
    op.create_table(
        "scenario_verification_results",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("scenario_execution_id", sa.String(length=64), nullable=False),
        sa.Column("total_stages", sa.Integer(), nullable=False, server_default="20"),
        sa.Column("verified_stages", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("degraded_stages", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_stages", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("missing_stages", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("provenance_integrity", sa.String(length=32), nullable=False, server_default="UNVERIFIED"),
        sa.Column("ledger_integrity", sa.String(length=32), nullable=False, server_default="UNVERIFIED"),
        sa.Column("merkle_integrity", sa.String(length=32), nullable=False, server_default="UNVERIFIED"),
        sa.Column("overall_verification_status", sa.String(length=32), nullable=False, server_default="UNVERIFIED"),
        sa.Column("verification_summary_json", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("verification_hash", sa.String(length=64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_by_user_id", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["scenario_execution_id"],
            ["sentinel.scenario_executions.id"],
            name="fk_verification_results_exec_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("scenario_execution_id", name="uq_scenario_verif_exec_id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_scenario_verif_exec_id",
        "scenario_verification_results",
        ["scenario_execution_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_scenario_verif_status",
        "scenario_verification_results",
        ["overall_verification_status"],
        unique=False,
        schema="sentinel",
    )

    # 7. Create sentinel.scenario_executive_impacts
    op.create_table(
        "scenario_executive_impacts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("scenario_execution_id", sa.String(length=64), nullable=False),
        sa.Column("pre_executive_posture_id", sa.String(length=64), nullable=True),
        sa.Column("post_executive_posture_id", sa.String(length=64), nullable=True),
        sa.Column("pre_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("post_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("score_delta", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("pre_status", sa.String(length=32), nullable=False, server_default="HEALTHY"),
        sa.Column("post_status", sa.String(length=32), nullable=False, server_default="HEALTHY"),
        sa.Column("impacted_domains_json", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("top_risk_driver_delta_json", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("impact_classification", sa.String(length=32), nullable=False, server_default="NEUTRAL"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["scenario_execution_id"],
            ["sentinel.scenario_executions.id"],
            name="fk_executive_impacts_exec_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("scenario_execution_id", name="uq_scenario_impact_exec_id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_scenario_impact_exec_id",
        "scenario_executive_impacts",
        ["scenario_execution_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_scenario_impact_classification",
        "scenario_executive_impacts",
        ["impact_classification"],
        unique=False,
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_table("scenario_executive_impacts", schema="sentinel")
    op.drop_table("scenario_verification_results", schema="sentinel")
    op.drop_table("scenario_artifact_bindings", schema="sentinel")
    op.drop_table("scenario_stage_executions", schema="sentinel")
    op.drop_table("scenario_executions", schema="sentinel")
    op.drop_table("security_scenario_versions", schema="sentinel")
    op.drop_table("security_scenarios", schema="sentinel")
