"""create_compliance_intelligence_tables

Revision ID: s9t0u1v2w3x4
Revises: r8s9t0u1v2w3
Create Date: 2026-09-09 00:00:00.000000

Sprint 11A — Compliance Intelligence, Security Control Governance & Evidence-Backed Compliance Assurance.
Creates:
- sentinel.compliance_frameworks
- sentinel.compliance_requirements
- sentinel.security_controls
- sentinel.framework_control_mappings
- sentinel.control_evidence_bindings
- sentinel.control_effectiveness_evaluations
- sentinel.compliance_gaps
- sentinel.compliance_findings
- sentinel.compliance_posture_evaluations
- sentinel.compliance_reviews
- sentinel.compliance_provenance_records
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "s9t0u1v2w3x4"
down_revision: Union[str, None] = "r8s9t0u1v2w3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. compliance_frameworks
    op.create_table(
        "compliance_frameworks",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("framework_code", sa.String(length=64), nullable=False),
        sa.Column("framework_name", sa.String(length=255), nullable=False),
        sa.Column("framework_version", sa.String(length=32), nullable=False, server_default="1.0"),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("framework_category", sa.String(length=64), nullable=False, server_default="SECURITY_BASELINE"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("publisher", sa.String(length=255), nullable=False, server_default="SentinelTrace Architecture"),
        sa.Column("effective_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", JSON(), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False, server_default="SYSTEM"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("framework_code", name="uq_compliance_framework_code"),
        schema="sentinel",
    )
    op.create_index("ix_compliance_frameworks_code", "compliance_frameworks", ["framework_code"], unique=True, schema="sentinel")
    op.create_index("ix_compliance_frameworks_status", "compliance_frameworks", ["status"], schema="sentinel")

    # 2. compliance_requirements
    op.create_table(
        "compliance_requirements",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("framework_id", sa.String(length=64), nullable=False),
        sa.Column("requirement_code", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("requirement_category", sa.String(length=64), nullable=False, server_default="TECHNICAL"),
        sa.Column("importance_weight", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("verification_required", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("evidence_freshness_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["framework_id"], ["sentinel.compliance_frameworks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("framework_id", "requirement_code", name="uq_framework_requirement_code"),
        sa.CheckConstraint("importance_weight > 0", name="chk_req_importance_weight_positive"),
        schema="sentinel",
    )
    op.create_index("ix_compliance_requirements_fw_code", "compliance_requirements", ["framework_id", "requirement_code"], schema="sentinel")
    op.create_index("ix_compliance_requirements_status", "compliance_requirements", ["status"], schema="sentinel")

    # 3. security_controls
    op.create_table(
        "security_controls",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("control_code", sa.String(length=64), nullable=False),
        sa.Column("control_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("control_domain", sa.String(length=64), nullable=False),
        sa.Column("control_owner", sa.String(length=64), nullable=False, server_default="SecOps"),
        sa.Column("control_type", sa.String(length=32), nullable=False, server_default="DETECTIVE"),
        sa.Column("criticality", sa.String(length=32), nullable=False, server_default="HIGH"),
        sa.Column("expected_state", sa.String(length=64), nullable=False, server_default="OPERATIONAL"),
        sa.Column("verification_frequency", sa.String(length=32), nullable=False, server_default="CONTINUOUS"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("control_code", name="uq_security_controls_code"),
        schema="sentinel",
    )
    op.create_index("ix_security_controls_code", "security_controls", ["control_code"], unique=True, schema="sentinel")
    op.create_index("ix_security_controls_domain", "security_controls", ["control_domain"], schema="sentinel")
    op.create_index("ix_security_controls_status", "security_controls", ["status"], schema="sentinel")

    # 4. framework_control_mappings
    op.create_table(
        "framework_control_mappings",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("framework_requirement_id", sa.String(length=64), nullable=False),
        sa.Column("security_control_id", sa.String(length=64), nullable=False),
        sa.Column("mapping_strength", sa.String(length=32), nullable=False, server_default="PRIMARY"),
        sa.Column("mapping_rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("mandatory", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["framework_requirement_id"], ["sentinel.compliance_requirements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["security_control_id"], ["sentinel.security_controls.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("framework_requirement_id", "security_control_id", name="uq_requirement_control_mapping"),
        schema="sentinel",
    )
    op.create_index("ix_fcm_req_ctrl", "framework_control_mappings", ["framework_requirement_id", "security_control_id"], schema="sentinel")

    # 5. control_evidence_bindings
    op.create_table(
        "control_evidence_bindings",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("security_control_id", sa.String(length=64), nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("evidence_id", sa.String(length=128), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("source_stage", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("binding_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("binding_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["security_control_id"], ["sentinel.security_controls.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index("ix_ceb_ctrl_evidence", "control_evidence_bindings", ["security_control_id", "evidence_type", "evidence_id"], schema="sentinel")
    op.create_index("ix_ceb_binding_hash", "control_evidence_bindings", ["binding_hash"], schema="sentinel")

    # 6. control_effectiveness_evaluations
    op.create_table(
        "control_effectiveness_evaluations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("evaluation_number", sa.String(length=32), nullable=False),
        sa.Column("security_control_id", sa.String(length=64), nullable=False),
        sa.Column("evaluation_status", sa.String(length=32), nullable=False, server_default="EFFECTIVE"),
        sa.Column("effectiveness_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("evidence_coverage", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("freshness_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("operational_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("integrity_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("deductions_json", JSON(), nullable=False),
        sa.Column("reasoning_json", JSON(), nullable=False),
        sa.Column("evaluation_hash", sa.String(length=64), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evaluated_by", sa.String(length=64), nullable=False, server_default="SYSTEM"),
        sa.ForeignKeyConstraint(["security_control_id"], ["sentinel.security_controls.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evaluation_number", name="uq_cee_evaluation_number"),
        sa.CheckConstraint("effectiveness_score >= 0.0 AND effectiveness_score <= 100.0", name="chk_cee_eff_score_range"),
        sa.CheckConstraint("confidence_score >= 0.0 AND confidence_score <= 100.0", name="chk_cee_conf_score_range"),
        schema="sentinel",
    )
    op.create_index("ix_cee_eval_number", "control_effectiveness_evaluations", ["evaluation_number"], unique=True, schema="sentinel")
    op.create_index("ix_cee_ctrl_status", "control_effectiveness_evaluations", ["security_control_id", "evaluation_status"], schema="sentinel")
    op.create_index("ix_cee_eval_hash", "control_effectiveness_evaluations", ["evaluation_hash"], schema="sentinel")

    # 7. compliance_gaps
    op.create_table(
        "compliance_gaps",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("gap_number", sa.String(length=32), nullable=False),
        sa.Column("framework_requirement_id", sa.String(length=64), nullable=True),
        sa.Column("security_control_id", sa.String(length=64), nullable=True),
        sa.Column("gap_category", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="MEDIUM"),
        sa.Column("gap_status", sa.String(length=32), nullable=False, server_default="OPEN"),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("root_cause", sa.Text(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_evidence_id", sa.String(length=128), nullable=True),
        sa.Column("deduplication_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("gap_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["framework_requirement_id"], ["sentinel.compliance_requirements.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["security_control_id"], ["sentinel.security_controls.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("gap_number", name="uq_compliance_gaps_number"),
        schema="sentinel",
    )
    op.create_index("ix_compliance_gaps_number", "compliance_gaps", ["gap_number"], unique=True, schema="sentinel")
    op.create_index("ix_compliance_gaps_fingerprint", "compliance_gaps", ["deduplication_fingerprint"], schema="sentinel")
    op.create_index("ix_compliance_gaps_status_sev", "compliance_gaps", ["gap_status", "severity"], schema="sentinel")

    # 8. compliance_findings
    op.create_table(
        "compliance_findings",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("finding_number", sa.String(length=32), nullable=False),
        sa.Column("framework_requirement_id", sa.String(length=64), nullable=True),
        sa.Column("security_control_id", sa.String(length=64), nullable=True),
        sa.Column("finding_type", sa.String(length=64), nullable=False, server_default="OBSERVATION"),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("evidence_summary", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False, server_default="HIGH"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False),
        sa.Column("reviewed_by_user_id", sa.String(length=64), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finding_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["framework_requirement_id"], ["sentinel.compliance_requirements.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["security_control_id"], ["sentinel.security_controls.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_number", name="uq_compliance_findings_number"),
        schema="sentinel",
    )
    op.create_index("ix_compliance_findings_number", "compliance_findings", ["finding_number"], unique=True, schema="sentinel")
    op.create_index("ix_compliance_findings_status", "compliance_findings", ["status"], schema="sentinel")
    op.create_index("ix_compliance_findings_hash", "compliance_findings", ["finding_hash"], schema="sentinel")

    # 9. compliance_posture_evaluations
    op.create_table(
        "compliance_posture_evaluations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("evaluation_number", sa.String(length=32), nullable=False),
        sa.Column("framework_id", sa.String(length=64), nullable=False),
        sa.Column("overall_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("posture_status", sa.String(length=32), nullable=False, server_default="COMPLIANT"),
        sa.Column("requirements_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requirements_effective", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requirements_partial", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requirements_failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requirements_unknown", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_gaps", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high_gaps", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hard_failure_override", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("override_reason", sa.Text(), nullable=True),
        sa.Column("evaluation_reasoning_json", JSON(), nullable=False),
        sa.Column("evaluation_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=64), nullable=False, server_default="SYSTEM"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["framework_id"], ["sentinel.compliance_frameworks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evaluation_number", name="uq_cpe_evaluation_number"),
        sa.CheckConstraint("overall_score >= 0.0 AND overall_score <= 100.0", name="chk_cpe_overall_score_range"),
        schema="sentinel",
    )
    op.create_index("ix_cpe_number", "compliance_posture_evaluations", ["evaluation_number"], unique=True, schema="sentinel")
    op.create_index("ix_cpe_fw_status", "compliance_posture_evaluations", ["framework_id", "posture_status"], schema="sentinel")
    op.create_index("ix_cpe_eval_hash", "compliance_posture_evaluations", ["evaluation_hash"], schema="sentinel")

    # 10. compliance_reviews
    op.create_table(
        "compliance_reviews",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("compliance_posture_evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("review_action", sa.String(length=32), nullable=False),
        sa.Column("review_comment", sa.Text(), nullable=False, server_default=""),
        sa.Column("reviewer_user_id", sa.String(length=64), nullable=False),
        sa.Column("review_hash", sa.String(length=64), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["compliance_posture_evaluation_id"], ["sentinel.compliance_posture_evaluations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index("ix_compliance_reviews_cpe_id", "compliance_reviews", ["compliance_posture_evaluation_id"], schema="sentinel")
    op.create_index("ix_compliance_reviews_reviewer", "compliance_reviews", ["reviewer_user_id"], schema="sentinel")
    op.create_index("ix_compliance_reviews_hash", "compliance_reviews", ["review_hash"], schema="sentinel")

    # 11. compliance_provenance_records
    op.create_table(
        "compliance_provenance_records",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("posture_evaluation_id", sa.String(length=64), nullable=False),
        sa.Column("stage_number", sa.Integer(), nullable=False),
        sa.Column("stage_name", sa.String(length=128), nullable=False),
        sa.Column("artifact_type", sa.String(length=64), nullable=False),
        sa.Column("artifact_id", sa.String(length=128), nullable=False),
        sa.Column("artifact_hash", sa.String(length=64), nullable=True),
        sa.Column("previous_stage_hash", sa.String(length=64), nullable=True),
        sa.Column("stage_hash", sa.String(length=64), nullable=False),
        sa.Column("integrity_status", sa.String(length=32), nullable=False, server_default="VERIFIED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["posture_evaluation_id"], ["sentinel.compliance_posture_evaluations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="sentinel",
    )
    op.create_index("ix_cpr_posture_stage", "compliance_provenance_records", ["posture_evaluation_id", "stage_number"], schema="sentinel")
    op.create_index("ix_cpr_stage_hash", "compliance_provenance_records", ["stage_hash"], schema="sentinel")


def downgrade() -> None:
    op.drop_table("compliance_provenance_records", schema="sentinel")
    op.drop_table("compliance_reviews", schema="sentinel")
    op.drop_table("compliance_posture_evaluations", schema="sentinel")
    op.drop_table("compliance_findings", schema="sentinel")
    op.drop_table("compliance_gaps", schema="sentinel")
    op.drop_table("control_effectiveness_evaluations", schema="sentinel")
    op.drop_table("control_evidence_bindings", schema="sentinel")
    op.drop_table("framework_control_mappings", schema="sentinel")
    op.drop_table("security_controls", schema="sentinel")
    op.drop_table("compliance_requirements", schema="sentinel")
    op.drop_table("compliance_frameworks", schema="sentinel")
