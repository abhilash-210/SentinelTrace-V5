"""create_detection_rule_governance_tables

Revision ID: j0k1l2m3n4o5
Revises: i9j0k1l2m3n4
Create Date: 2026-09-07 02:00:00.000000

Sprint 6C — Detection Rule Governance, Dual-Control Approval, Rule Versioning, Version Impact Analysis, and Immutable Governance Auditability.
Creates:
- sentinel.detection_rule_versions: Immutable version snapshots for detection rules
- sentinel.detection_rule_version_dependencies: Version-scoped canonical field dependencies
- sentinel.detection_rule_approval_requests: Dual-control maker-checker approval requests
- sentinel.detection_rule_version_impacts: Stored deterministic version comparison impacts
- sentinel.detection_rule_governance_events: Append-only tamper-evident governance audit log
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "j0k1l2m3n4o5"
down_revision: Union[str, None] = "i9j0k1l2m3n4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.detection_rule_versions
    op.create_table(
        "detection_rule_versions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("version_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("parent_version_id", sa.String(length=64), nullable=True),
        sa.Column("rule_name", sa.String(length=255), nullable=False),
        sa.Column("vendor_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("query_signature", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="MEDIUM"),
        sa.Column("mitre_techniques", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("submitted_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("approval_decision", sa.String(length=32), nullable=True),
        sa.Column("approval_comment", sa.Text(), nullable=True),
        sa.Column("risk_acknowledged", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("risk_acknowledgement_comment", sa.Text(), nullable=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("activated_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_by_version_id", sa.String(length=64), nullable=True),
        sa.Column("version_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["sentinel.detection_rules.rule_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rule_id", "version_number", name="uq_rule_version_number"),
        schema="sentinel",
    )
    op.create_index(
        "ix_rule_versions_version_id",
        "detection_rule_versions",
        ["version_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_rule_versions_rule_id",
        "detection_rule_versions",
        ["rule_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_rule_versions_status",
        "detection_rule_versions",
        ["status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_rule_versions_version_hash",
        "detection_rule_versions",
        ["version_hash"],
        schema="sentinel",
    )

    # 2. Create sentinel.detection_rule_version_dependencies
    op.create_table(
        "detection_rule_version_dependencies",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("version_id", sa.String(length=64), nullable=False),
        sa.Column("canonical_field", sa.String(length=100), nullable=False),
        sa.Column("dependency_type", sa.String(length=32), nullable=False, server_default="REQUIRED"),
        sa.Column("is_protected_field", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["sentinel.detection_rule_versions.version_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_ver_deps_version_id",
        "detection_rule_version_dependencies",
        ["version_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ver_deps_canonical_field",
        "detection_rule_version_dependencies",
        ["canonical_field"],
        schema="sentinel",
    )

    # 3. Create sentinel.detection_rule_approval_requests
    op.create_table(
        "detection_rule_approval_requests",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("approval_request_id", sa.String(length=64), nullable=False),
        sa.Column("version_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("submitted_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("reviewed_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision", sa.String(length=32), nullable=True),
        sa.Column("review_comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["sentinel.detection_rule_versions.version_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["sentinel.detection_rules.rule_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_dr_approval_req_id",
        "detection_rule_approval_requests",
        ["approval_request_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_dr_approval_version_id",
        "detection_rule_approval_requests",
        ["version_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_dr_approval_rule_id",
        "detection_rule_approval_requests",
        ["rule_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_dr_approval_status",
        "detection_rule_approval_requests",
        ["status"],
        schema="sentinel",
    )

    # 4. Create sentinel.detection_rule_version_impacts
    op.create_table(
        "detection_rule_version_impacts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("impact_id", sa.String(length=64), nullable=False),
        sa.Column("source_version_id", sa.String(length=64), nullable=True),
        sa.Column("target_version_id", sa.String(length=64), nullable=False),
        sa.Column("impact_level", sa.String(length=32), nullable=False),
        sa.Column("query_changed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("severity_changed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("vendor_scope_changed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("mitre_changed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("dependencies_added", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("dependencies_removed", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("protected_fields_added", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("trust_risk_delta", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("blast_radius_summary", sa.Text(), nullable=False),
        sa.Column("impact_details", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["target_version_id"],
            ["sentinel.detection_rule_versions.version_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_ver_impact_impact_id",
        "detection_rule_version_impacts",
        ["impact_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_ver_impact_source_id",
        "detection_rule_version_impacts",
        ["source_version_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ver_impact_target_id",
        "detection_rule_version_impacts",
        ["target_version_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ver_impact_level",
        "detection_rule_version_impacts",
        ["impact_level"],
        schema="sentinel",
    )

    # 5. Create sentinel.detection_rule_governance_events
    op.create_table(
        "detection_rule_governance_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("version_id", sa.String(length=64), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id", sa.String(length=64), nullable=False),
        sa.Column("actor_role", sa.String(length=32), nullable=False),
        sa.Column("previous_status", sa.String(length=32), nullable=True),
        sa.Column("new_status", sa.String(length=32), nullable=True),
        sa.Column("event_payload", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_dr_gov_events_event_id",
        "detection_rule_governance_events",
        ["event_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_dr_gov_events_rule_id",
        "detection_rule_governance_events",
        ["rule_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_dr_gov_events_version_id",
        "detection_rule_governance_events",
        ["version_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_dr_gov_events_event_type",
        "detection_rule_governance_events",
        ["event_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_dr_gov_events_actor",
        "detection_rule_governance_events",
        ["actor_user_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_dr_gov_events_created_at",
        "detection_rule_governance_events",
        ["created_at"],
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_table("detection_rule_governance_events", schema="sentinel")
    op.drop_table("detection_rule_version_impacts", schema="sentinel")
    op.drop_table("detection_rule_approval_requests", schema="sentinel")
    op.drop_table("detection_rule_version_dependencies", schema="sentinel")
    op.drop_table("detection_rule_versions", schema="sentinel")
