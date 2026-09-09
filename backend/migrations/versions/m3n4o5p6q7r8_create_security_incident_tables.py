"""create_security_incident_investigation_tables

Revision ID: m3n4o5p6q7r8
Revises: l2m3n4o5p6q7
Create Date: 2026-09-08 10:00:00.000000

Sprint 8A — Security Incident Correlation & Investigation Foundation.
Creates:
- sentinel.security_incidents: Formal security incident entities connecting correlated risks and trust alerts
- sentinel.incident_signals: Explicit tracking of contributing security signals and relationship types
- sentinel.incident_evidence_links: References linking upstream immutable evidence without data mutation
- sentinel.incident_findings: Analyst-authored investigation findings preserving attribution
- sentinel.incident_timeline_events: Append-only investigation timeline events
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "m3n4o5p6q7r8"
down_revision: Union[str, None] = "l2m3n4o5p6q7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.security_incidents
    op.create_table(
        "security_incidents",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("incident_number", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("incident_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("priority", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="OPEN"),
        sa.Column("source_correlation_id", sa.String(length=64), nullable=True),
        sa.Column("source_cluster_key", sa.String(length=128), nullable=True),
        sa.Column("root_cause_summary", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("affected_signal_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("affected_rule_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("affected_field_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("assigned_to_user_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["source_correlation_id"],
            ["sentinel.risk_correlations.correlation_id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_sec_inc_incident_id",
        "security_incidents",
        ["incident_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_sec_inc_incident_number",
        "security_incidents",
        ["incident_number"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_sec_inc_type",
        "security_incidents",
        ["incident_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_sec_inc_severity",
        "security_incidents",
        ["severity"],
        schema="sentinel",
    )
    op.create_index(
        "ix_sec_inc_priority",
        "security_incidents",
        ["priority"],
        schema="sentinel",
    )
    op.create_index(
        "ix_sec_inc_status",
        "security_incidents",
        ["status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_sec_inc_assigned",
        "security_incidents",
        ["assigned_to_user_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_sec_inc_created_at",
        "security_incidents",
        ["created_at"],
        schema="sentinel",
    )

    # 2. Create sentinel.incident_signals
    op.create_table(
        "incident_signals",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("incident_signal_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("signal_type", sa.String(length=64), nullable=False),
        sa.Column("signal_id", sa.String(length=128), nullable=False),
        sa.Column("relationship_type", sa.String(length=64), nullable=False, server_default="CONTRIBUTING_SIGNAL"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["sentinel.security_incidents.incident_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "signal_type", "signal_id", name="uq_incident_signal_unique"),
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_sig_incident_id",
        "incident_signals",
        ["incident_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_sig_signal_type",
        "incident_signals",
        ["signal_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_sig_signal_id",
        "incident_signals",
        ["signal_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_sig_created_at",
        "incident_signals",
        ["created_at"],
        schema="sentinel",
    )

    # 3. Create sentinel.incident_evidence_links
    op.create_table(
        "incident_evidence_links",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("link_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("evidence_id", sa.String(length=128), nullable=False),
        sa.Column("relationship", sa.String(length=64), nullable=False, server_default="SUPPORTING"),
        sa.Column("linked_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["sentinel.security_incidents.incident_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "evidence_type", "evidence_id", name="uq_incident_evidence_unique"),
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_ev_incident_id",
        "incident_evidence_links",
        ["incident_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_ev_evidence_type",
        "incident_evidence_links",
        ["evidence_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_ev_evidence_id",
        "incident_evidence_links",
        ["evidence_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_ev_linked_at",
        "incident_evidence_links",
        ["linked_at"],
        schema="sentinel",
    )

    # 4. Create sentinel.incident_findings
    op.create_table(
        "incident_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("finding_type", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="OPEN"),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["sentinel.security_incidents.incident_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_fnd_incident_id",
        "incident_findings",
        ["incident_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_fnd_type",
        "incident_findings",
        ["finding_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_fnd_status",
        "incident_findings",
        ["status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_fnd_created_at",
        "incident_findings",
        ["created_at"],
        schema="sentinel",
    )

    # 5. Create sentinel.incident_timeline_events
    op.create_table(
        "incident_timeline_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("timeline_event_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id", sa.String(length=64), nullable=True),
        sa.Column("event_data", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["sentinel.security_incidents.incident_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_tm_incident_id",
        "incident_timeline_events",
        ["incident_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_tm_event_type",
        "incident_timeline_events",
        ["event_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_tm_actor",
        "incident_timeline_events",
        ["actor_user_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_inc_tm_created_at",
        "incident_timeline_events",
        ["created_at"],
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_table("incident_timeline_events", schema="sentinel")
    op.drop_table("incident_findings", schema="sentinel")
    op.drop_table("incident_evidence_links", schema="sentinel")
    op.drop_table("incident_signals", schema="sentinel")
    op.drop_table("security_incidents", schema="sentinel")
