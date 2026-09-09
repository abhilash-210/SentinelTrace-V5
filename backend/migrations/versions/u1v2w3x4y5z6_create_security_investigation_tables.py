"""create_security_investigation_tables

Revision ID: u1v2w3x4y5z6
Revises: t0u1v2w3x4y5
Create Date: 2026-09-08 22:30:00.000000

Sprint 12A: Unified SOC Investigation & Security Case Management
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'u1v2w3x4y5z6'
down_revision: Union[str, None] = 't0u1v2w3x4y5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. security_investigation_cases
    op.create_table(
        'security_investigation_cases',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('case_number', sa.String(length=32), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('priority', sa.String(length=32), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('investigation_type', sa.String(length=64), nullable=False),
        sa.Column('source_domain', sa.String(length=64), nullable=False),
        sa.Column('created_by', sa.String(length=64), nullable=False),
        sa.Column('assigned_to', sa.String(length=64), nullable=True),
        sa.Column('opened_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolution', sa.String(length=64), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
        sa.Column('priority_score', sa.Float(), nullable=False),
        sa.Column('priority_drivers', sa.JSON(), nullable=False),
        sa.Column('hard_failure_override', sa.Boolean(), nullable=False),
        sa.Column('canonical_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_number'),
        schema='sentinel'
    )
    op.create_index('ix_sic_case_number', 'security_investigation_cases', ['case_number'], unique=True, schema='sentinel')
    op.create_index('ix_sic_status', 'security_investigation_cases', ['status'], unique=False, schema='sentinel')
    op.create_index('ix_sic_priority', 'security_investigation_cases', ['priority'], unique=False, schema='sentinel')
    op.create_index('ix_sic_severity', 'security_investigation_cases', ['severity'], unique=False, schema='sentinel')
    op.create_index('ix_sic_investigation_type', 'security_investigation_cases', ['investigation_type'], unique=False, schema='sentinel')
    op.create_index('ix_sic_source_domain', 'security_investigation_cases', ['source_domain'], unique=False, schema='sentinel')
    op.create_index('ix_sic_assigned_to', 'security_investigation_cases', ['assigned_to'], unique=False, schema='sentinel')
    op.create_index('ix_sic_created_at', 'security_investigation_cases', ['created_at'], unique=False, schema='sentinel')

    # 2. investigation_artifact_bindings
    op.create_table(
        'investigation_artifact_bindings',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('artifact_type', sa.String(length=64), nullable=False),
        sa.Column('artifact_id', sa.String(length=128), nullable=False),
        sa.Column('source_domain', sa.String(length=64), nullable=False),
        sa.Column('canonical_hash', sa.String(length=64), nullable=False),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('binding_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['sentinel.security_investigation_cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_id', 'artifact_type', 'artifact_id', name='uq_case_artifact_binding'),
        schema='sentinel'
    )
    op.create_index('ix_iab_case_id', 'investigation_artifact_bindings', ['case_id'], unique=False, schema='sentinel')
    op.create_index('ix_iab_artifact_type', 'investigation_artifact_bindings', ['artifact_type'], unique=False, schema='sentinel')
    op.create_index('ix_iab_artifact_id', 'investigation_artifact_bindings', ['artifact_id'], unique=False, schema='sentinel')
    op.create_index('ix_iab_source_domain', 'investigation_artifact_bindings', ['source_domain'], unique=False, schema='sentinel')

    # 3. investigation_hypotheses
    op.create_table(
        'investigation_hypotheses',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('hypothesis_title', sa.String(length=255), nullable=False),
        sa.Column('hypothesis_statement', sa.Text(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('deductions_json', sa.JSON(), nullable=False),
        sa.Column('supporting_evidence_ids', sa.JSON(), nullable=False),
        sa.Column('analyst_notes', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['sentinel.security_investigation_cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_ih_case_id', 'investigation_hypotheses', ['case_id'], unique=False, schema='sentinel')
    op.create_index('ix_ih_status', 'investigation_hypotheses', ['status'], unique=False, schema='sentinel')

    # 4. investigation_findings
    op.create_table(
        'investigation_findings',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('finding_type', sa.String(length=64), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('evidence_summary', sa.Text(), nullable=False),
        sa.Column('analyst_conclusion', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('mitre_technique_id', sa.String(length=32), nullable=True),
        sa.Column('created_by', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['sentinel.security_investigation_cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_if_case_id', 'investigation_findings', ['case_id'], unique=False, schema='sentinel')
    op.create_index('ix_if_finding_type', 'investigation_findings', ['finding_type'], unique=False, schema='sentinel')
    op.create_index('ix_if_status', 'investigation_findings', ['status'], unique=False, schema='sentinel')

    # 5. investigation_timeline_events
    op.create_table(
        'investigation_timeline_events',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('source_domain', sa.String(length=64), nullable=False),
        sa.Column('artifact_reference', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('hash_reference', sa.String(length=64), nullable=False),
        sa.Column('sequence_order', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['sentinel.security_investigation_cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_ite_case_id', 'investigation_timeline_events', ['case_id'], unique=False, schema='sentinel')
    op.create_index('ix_ite_timestamp', 'investigation_timeline_events', ['timestamp'], unique=False, schema='sentinel')
    op.create_index('ix_ite_event_type', 'investigation_timeline_events', ['event_type'], unique=False, schema='sentinel')

    # 6. investigation_impact_assessments
    op.create_table(
        'investigation_impact_assessments',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('confidentiality_impact', sa.String(length=32), nullable=False),
        sa.Column('integrity_impact', sa.String(length=32), nullable=False),
        sa.Column('availability_impact', sa.String(length=32), nullable=False),
        sa.Column('business_impact', sa.String(length=32), nullable=False),
        sa.Column('compliance_impact', sa.String(length=32), nullable=False),
        sa.Column('overall_impact', sa.String(length=32), nullable=False),
        sa.Column('impact_score', sa.Float(), nullable=False),
        sa.Column('assessment_notes', sa.Text(), nullable=False),
        sa.Column('assessed_by', sa.String(length=64), nullable=False),
        sa.Column('assessment_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['sentinel.security_investigation_cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_iia_case_id', 'investigation_impact_assessments', ['case_id'], unique=False, schema='sentinel')

    # 7. investigation_reviews
    op.create_table(
        'investigation_reviews',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('proposed_by_user_id', sa.String(length=64), nullable=False),
        sa.Column('proposed_resolution', sa.String(length=64), nullable=False),
        sa.Column('proposed_notes', sa.Text(), nullable=True),
        sa.Column('reviewer_user_id', sa.String(length=64), nullable=True),
        sa.Column('decision', sa.String(length=32), nullable=False),
        sa.Column('review_notes', sa.Text(), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('governance_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['sentinel.security_investigation_cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_ir_case_id', 'investigation_reviews', ['case_id'], unique=False, schema='sentinel')
    op.create_index('ix_ir_decision', 'investigation_reviews', ['decision'], unique=False, schema='sentinel')

    # 8. investigation_case_resolutions
    op.create_table(
        'investigation_case_resolutions',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('resolution_type', sa.String(length=64), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('containment_verified', sa.Boolean(), nullable=False),
        sa.Column('root_cause_summary', sa.Text(), nullable=True),
        sa.Column('resolved_by', sa.String(length=64), nullable=False),
        sa.Column('reviewer_id', sa.String(length=64), nullable=False),
        sa.Column('resolution_hash', sa.String(length=64), nullable=False),
        sa.Column('ledger_reference', sa.String(length=128), nullable=True),
        sa.Column('merkle_reference', sa.String(length=128), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['sentinel.security_investigation_cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_icr_case_id', 'investigation_case_resolutions', ['case_id'], unique=False, schema='sentinel')
    op.create_index('ix_icr_resolution_type', 'investigation_case_resolutions', ['resolution_type'], unique=False, schema='sentinel')

    # 9. investigation_provenance_records
    op.create_table(
        'investigation_provenance_records',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('provenance_stage', sa.String(length=64), nullable=False),
        sa.Column('stage_order', sa.Integer(), nullable=False),
        sa.Column('entity_type', sa.String(length=64), nullable=False),
        sa.Column('entity_reference', sa.String(length=128), nullable=False),
        sa.Column('previous_hash', sa.String(length=64), nullable=False),
        sa.Column('current_hash', sa.String(length=64), nullable=False),
        sa.Column('ledger_reference', sa.String(length=128), nullable=True),
        sa.Column('merkle_reference', sa.String(length=128), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['sentinel.security_investigation_cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_id', 'stage_order', name='uq_case_provenance_stage_order'),
        schema='sentinel'
    )
    op.create_index('ix_ipr_case_id', 'investigation_provenance_records', ['case_id'], unique=False, schema='sentinel')
    op.create_index('ix_ipr_stage', 'investigation_provenance_records', ['provenance_stage'], unique=False, schema='sentinel')
    op.create_index('ix_ipr_order', 'investigation_provenance_records', ['stage_order'], unique=False, schema='sentinel')


def downgrade() -> None:
    op.drop_table('investigation_provenance_records', schema='sentinel')
    op.drop_table('investigation_case_resolutions', schema='sentinel')
    op.drop_table('investigation_reviews', schema='sentinel')
    op.drop_table('investigation_impact_assessments', schema='sentinel')
    op.drop_table('investigation_timeline_events', schema='sentinel')
    op.drop_table('investigation_findings', schema='sentinel')
    op.drop_table('investigation_hypotheses', schema='sentinel')
    op.drop_table('investigation_artifact_bindings', schema='sentinel')
    op.drop_table('security_investigation_cases', schema='sentinel')
