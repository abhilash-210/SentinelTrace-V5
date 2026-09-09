"""create_incident_response_governance_tables

Revision ID: n4o5p6q7r8s9
Revises: m3n4o5p6q7r8
Create Date: 2026-09-08 12:00:00.000000

Sprint 8B — Incident Response Governance, Containment Decision Engine & Human Authorization.
Creates:
- sentinel.incident_response_playbooks: Deterministic incident response playbooks
- sentinel.incident_playbook_actions: Ordered actions per playbook with dual-control requirements
- sentinel.incident_response_recommendations: Immutable deterministic recommendations from incident context
- sentinel.incident_containment_requests: Central containment lifecycle governance requests
- sentinel.incident_response_approvals: Immutable dual-control review records (Maker-Checker)
- sentinel.incident_response_executions: Immutable attestations of human operator execution
- sentinel.incident_response_verifications: Immutable post-containment verification records
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "n4o5p6q7r8s9"
down_revision: Union[str, None] = "m3n4o5p6q7r8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.incident_response_playbooks
    op.create_table(
        "incident_response_playbooks",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("playbook_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("incident_category", sa.String(length=64), nullable=False),
        sa.Column("minimum_severity", sa.String(length=32), nullable=False, server_default="LOW"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False, server_default="SYSTEM"),
        sa.Column("playbook_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_irp_playbook_id",
        "incident_response_playbooks",
        ["playbook_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_irp_category",
        "incident_response_playbooks",
        ["incident_category"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irp_min_severity",
        "incident_response_playbooks",
        ["minimum_severity"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irp_status",
        "incident_response_playbooks",
        ["status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irp_is_active",
        "incident_response_playbooks",
        ["is_active"],
        schema="sentinel",
    )

    # 2. Create sentinel.incident_playbook_actions
    op.create_table(
        "incident_playbook_actions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("action_id", sa.String(length=64), nullable=False),
        sa.Column("playbook_id", sa.String(length=64), nullable=False),
        sa.Column("action_key", sa.String(length=64), nullable=False),
        sa.Column("action_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("impact_level", sa.String(length=32), nullable=False, server_default="LOW_IMPACT"),
        sa.Column("requires_dual_control", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_mandatory", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["playbook_id"],
            ["sentinel.incident_response_playbooks.playbook_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_ipa_playbook_id",
        "incident_playbook_actions",
        ["playbook_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ipa_action_key",
        "incident_playbook_actions",
        ["action_key"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ipa_action_type",
        "incident_playbook_actions",
        ["action_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ipa_impact_level",
        "incident_playbook_actions",
        ["impact_level"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ipa_seq",
        "incident_playbook_actions",
        ["playbook_id", "sequence_number"],
        schema="sentinel",
    )

    # 3. Create sentinel.incident_response_recommendations
    op.create_table(
        "incident_response_recommendations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("recommendation_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("playbook_id", sa.String(length=64), nullable=True),
        sa.Column("action_key", sa.String(length=64), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("priority", sa.String(length=32), nullable=False, server_default="P2"),
        sa.Column("impact_level", sa.String(length=32), nullable=False, server_default="LOW_IMPACT"),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("reasoning", sa.Text(), nullable=False),
        sa.Column("risk_context", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="RECOMMENDED"),
        sa.Column("recommendation_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["sentinel.security_incidents.incident_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["playbook_id"],
            ["sentinel.incident_response_playbooks.playbook_id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_irr_recommendation_id",
        "incident_response_recommendations",
        ["recommendation_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_irr_incident_id",
        "incident_response_recommendations",
        ["incident_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irr_playbook_id",
        "incident_response_recommendations",
        ["playbook_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irr_action_key",
        "incident_response_recommendations",
        ["action_key"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irr_priority",
        "incident_response_recommendations",
        ["priority"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irr_status",
        "incident_response_recommendations",
        ["status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irr_impact_level",
        "incident_response_recommendations",
        ["impact_level"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irr_created_at",
        "incident_response_recommendations",
        ["created_at"],
        schema="sentinel",
    )

    # 4. Create sentinel.incident_containment_requests
    op.create_table(
        "incident_containment_requests",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("recommendation_id", sa.String(length=64), nullable=True),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("action_description", sa.Text(), nullable=False),
        sa.Column("impact_level", sa.String(length=32), nullable=False, server_default="HIGH_IMPACT"),
        sa.Column("risk_justification", sa.Text(), nullable=False),
        sa.Column("proposed_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("reviewed_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("approved_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
        sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_attested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("governance_ledger_entry_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["sentinel.security_incidents.incident_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["recommendation_id"],
            ["sentinel.incident_response_recommendations.recommendation_id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_icr_request_id",
        "incident_containment_requests",
        ["request_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_icr_incident_id",
        "incident_containment_requests",
        ["incident_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_icr_recommendation_id",
        "incident_containment_requests",
        ["recommendation_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_icr_status",
        "incident_containment_requests",
        ["status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_icr_impact_level",
        "incident_containment_requests",
        ["impact_level"],
        schema="sentinel",
    )
    op.create_index(
        "ix_icr_proposed_by",
        "incident_containment_requests",
        ["proposed_by_user_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_icr_reviewed_by",
        "incident_containment_requests",
        ["reviewed_by_user_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_icr_created_at",
        "incident_containment_requests",
        ["created_at"],
        schema="sentinel",
    )

    # 5. Create sentinel.incident_response_approvals
    op.create_table(
        "incident_response_approvals",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("approval_id", sa.String(length=64), nullable=False),
        sa.Column("containment_request_id", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("decision_reason", sa.Text(), nullable=False),
        sa.Column("reviewer_user_id", sa.String(length=64), nullable=False),
        sa.Column("approval_hash", sa.String(length=64), nullable=False),
        sa.Column("governance_event_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["containment_request_id"],
            ["sentinel.incident_containment_requests.request_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_ira_approval_id",
        "incident_response_approvals",
        ["approval_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_ira_request_id",
        "incident_response_approvals",
        ["containment_request_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ira_decision",
        "incident_response_approvals",
        ["decision"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ira_reviewer",
        "incident_response_approvals",
        ["reviewer_user_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ira_created_at",
        "incident_response_approvals",
        ["created_at"],
        schema="sentinel",
    )

    # 6. Create sentinel.incident_response_executions
    op.create_table(
        "incident_response_executions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("execution_id", sa.String(length=64), nullable=False),
        sa.Column("containment_request_id", sa.String(length=64), nullable=False),
        sa.Column("execution_status", sa.String(length=32), nullable=False, server_default="EXECUTION_ATTESTED"),
        sa.Column("execution_notes", sa.Text(), nullable=False),
        sa.Column("executed_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("execution_reference", sa.String(length=128), nullable=False),
        sa.Column("attestation_hash", sa.String(length=64), nullable=False),
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["containment_request_id"],
            ["sentinel.incident_containment_requests.request_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_ire_execution_id",
        "incident_response_executions",
        ["execution_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_ire_request_id",
        "incident_response_executions",
        ["containment_request_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ire_status",
        "incident_response_executions",
        ["execution_status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ire_executed_by",
        "incident_response_executions",
        ["executed_by_user_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_ire_attested_at",
        "incident_response_executions",
        ["attested_at"],
        schema="sentinel",
    )

    # 7. Create sentinel.incident_response_verifications
    op.create_table(
        "incident_response_verifications",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("verification_id", sa.String(length=64), nullable=False),
        sa.Column("containment_request_id", sa.String(length=64), nullable=False),
        sa.Column("verification_status", sa.String(length=32), nullable=False, server_default="VERIFIED"),
        sa.Column("verification_method", sa.String(length=64), nullable=False),
        sa.Column("verification_evidence", sa.Text(), nullable=False),
        sa.Column("verified_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("verification_notes", sa.Text(), nullable=True),
        sa.Column("verification_hash", sa.String(length=64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["containment_request_id"],
            ["sentinel.incident_containment_requests.request_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index(
        "ix_irv_verification_id",
        "incident_response_verifications",
        ["verification_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_irv_request_id",
        "incident_response_verifications",
        ["containment_request_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irv_status",
        "incident_response_verifications",
        ["verification_status"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irv_method",
        "incident_response_verifications",
        ["verification_method"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irv_verified_by",
        "incident_response_verifications",
        ["verified_by_user_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_irv_verified_at",
        "incident_response_verifications",
        ["verified_at"],
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_table("incident_response_verifications", schema="sentinel")
    op.drop_table("incident_response_executions", schema="sentinel")
    op.drop_table("incident_response_approvals", schema="sentinel")
    op.drop_table("incident_containment_requests", schema="sentinel")
    op.drop_table("incident_response_recommendations", schema="sentinel")
    op.drop_table("incident_playbook_actions", schema="sentinel")
    op.drop_table("incident_response_playbooks", schema="sentinel")
