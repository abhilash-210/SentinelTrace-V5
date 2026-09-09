"""create_detection_rule_tables

Revision ID: h8i9j0k1l2m3
Revises: g7b8c9d0e1f2
Create Date: 2026-09-07 00:00:00.000000

Sprint 6A — Detection Rule Registry & Canonical Field Dependency Mapping.
Creates:
- sentinel.detection_rules: Detection rule registry with lifecycle governance
- sentinel.detection_rule_dependencies: Canonical field dependency DAG edges
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "h8i9j0k1l2m3"
down_revision: Union[str, None] = "g7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.detection_rules table
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_name", sa.String(length=255), nullable=False),
        sa.Column("vendor_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="MEDIUM"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("mitre_tactic", sa.String(length=100), nullable=True),
        sa.Column("mitre_technique", sa.String(length=100), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_rules_rule_id",
        "detection_rules",
        ["rule_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_rules_vendor_name",
        "detection_rules",
        ["vendor_name"],
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_rules_status",
        "detection_rules",
        ["status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_rules_severity",
        "detection_rules",
        ["severity"],
        schema="sentinel",
    )

    # 2. Create sentinel.detection_rule_dependencies table
    op.create_table(
        "detection_rule_dependencies",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("dependency_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("canonical_field", sa.String(length=100), nullable=False),
        sa.Column("dependency_type", sa.String(length=32), nullable=False, server_default="REQUIRED"),
        sa.Column("description", sa.Text(), nullable=True),
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
        "ix_detection_rule_deps_dep_id",
        "detection_rule_dependencies",
        ["dependency_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_rule_deps_rule_id",
        "detection_rule_dependencies",
        ["rule_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_detection_rule_deps_canonical_field",
        "detection_rule_dependencies",
        ["canonical_field"],
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_table("detection_rule_dependencies", schema="sentinel")
    op.drop_table("detection_rules", schema="sentinel")
