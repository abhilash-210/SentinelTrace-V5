"""create_security_analytics_tables

Revision ID: v2w3x4y5z6a7
Revises: u1v2w3x4y5z6
Create Date: 2026-09-09 10:30:00.000000

Sprint 12B: Security Analytics, Reporting & Evidence Intelligence
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'v2w3x4y5z6a7'
down_revision: Union[str, None] = 'u1v2w3x4y5z6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. security_analytics_snapshots
    op.create_table(
        'security_analytics_snapshots',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('snapshot_number', sa.String(length=64), nullable=False),
        sa.Column('period_type', sa.String(length=32), nullable=False),
        sa.Column('period_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('period_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('overall_security_score', sa.Float(), nullable=False),
        sa.Column('overall_confidence', sa.Float(), nullable=False),
        sa.Column('telemetry_completeness', sa.Float(), nullable=False),
        sa.Column('domains_evaluated', sa.Integer(), nullable=False),
        sa.Column('domains_unknown', sa.Integer(), nullable=False),
        sa.Column('critical_findings', sa.Integer(), nullable=False),
        sa.Column('high_findings', sa.Integer(), nullable=False),
        sa.Column('snapshot_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('snapshot_number'),
        schema='sentinel'
    )
    op.create_index('ix_sas_snapshot_number', 'security_analytics_snapshots', ['snapshot_number'], unique=True, schema='sentinel')
    op.create_index('ix_sas_period_type', 'security_analytics_snapshots', ['period_type'], unique=False, schema='sentinel')
    op.create_index('ix_sas_created_at', 'security_analytics_snapshots', ['created_at'], unique=False, schema='sentinel')

    # 2. security_metric_definitions
    op.create_table(
        'security_metric_definitions',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('metric_code', sa.String(length=64), nullable=False),
        sa.Column('metric_name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('domain', sa.String(length=64), nullable=False),
        sa.Column('unit', sa.String(length=32), nullable=False),
        sa.Column('direction', sa.String(length=32), nullable=False),
        sa.Column('calculation_method', sa.Text(), nullable=False),
        sa.Column('criticality', sa.String(length=32), nullable=False),
        sa.Column('requires_complete_telemetry', sa.Boolean(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('metric_code'),
        schema='sentinel'
    )
    op.create_index('ix_smd_metric_code', 'security_metric_definitions', ['metric_code'], unique=True, schema='sentinel')
    op.create_index('ix_smd_domain', 'security_metric_definitions', ['domain'], unique=False, schema='sentinel')
    op.create_index('ix_smd_criticality', 'security_metric_definitions', ['criticality'], unique=False, schema='sentinel')

    # 3. security_metric_evaluations
    op.create_table(
        'security_metric_evaluations',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('snapshot_id', sa.String(length=64), nullable=False),
        sa.Column('metric_definition_id', sa.String(length=64), nullable=False),
        sa.Column('metric_value', sa.Float(), nullable=False),
        sa.Column('metric_status', sa.String(length=32), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('sample_count', sa.Integer(), nullable=False),
        sa.Column('telemetry_state', sa.String(length=32), nullable=False),
        sa.Column('calculation_details_json', sa.JSON(), nullable=False),
        sa.Column('source_references_json', sa.JSON(), nullable=False),
        sa.Column('evaluation_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['snapshot_id'], ['sentinel.security_analytics_snapshots.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['metric_definition_id'], ['sentinel.security_metric_definitions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('snapshot_id', 'metric_definition_id', name='uq_snapshot_metric_def'),
        schema='sentinel'
    )
    op.create_index('ix_sme_snapshot_id', 'security_metric_evaluations', ['snapshot_id'], unique=False, schema='sentinel')
    op.create_index('ix_sme_metric_definition_id', 'security_metric_evaluations', ['metric_definition_id'], unique=False, schema='sentinel')
    op.create_index('ix_sme_status', 'security_metric_evaluations', ['metric_status'], unique=False, schema='sentinel')

    # 4. security_trend_snapshots
    op.create_table(
        'security_trend_snapshots',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('metric_definition_id', sa.String(length=64), nullable=False),
        sa.Column('current_snapshot_id', sa.String(length=64), nullable=False),
        sa.Column('previous_snapshot_id', sa.String(length=64), nullable=True),
        sa.Column('current_value', sa.Float(), nullable=False),
        sa.Column('previous_value', sa.Float(), nullable=True),
        sa.Column('delta_value', sa.Float(), nullable=True),
        sa.Column('delta_percentage', sa.Float(), nullable=True),
        sa.Column('trend_classification', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('reasoning_json', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['metric_definition_id'], ['sentinel.security_metric_definitions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['current_snapshot_id'], ['sentinel.security_analytics_snapshots.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['previous_snapshot_id'], ['sentinel.security_analytics_snapshots.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_sts_metric_def_id', 'security_trend_snapshots', ['metric_definition_id'], unique=False, schema='sentinel')
    op.create_index('ix_sts_current_snap_id', 'security_trend_snapshots', ['current_snapshot_id'], unique=False, schema='sentinel')
    op.create_index('ix_sts_classification', 'security_trend_snapshots', ['trend_classification'], unique=False, schema='sentinel')

    # 5. security_analytics_insights
    op.create_table(
        'security_analytics_insights',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('snapshot_id', sa.String(length=64), nullable=False),
        sa.Column('insight_code', sa.String(length=64), nullable=False),
        sa.Column('insight_type', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('rule_triggered', sa.String(length=128), nullable=False),
        sa.Column('supporting_metrics_json', sa.JSON(), nullable=False),
        sa.Column('source_references_json', sa.JSON(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('limitations_json', sa.JSON(), nullable=False),
        sa.Column('insight_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['snapshot_id'], ['sentinel.security_analytics_snapshots.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_sai_snapshot_id', 'security_analytics_insights', ['snapshot_id'], unique=False, schema='sentinel')
    op.create_index('ix_sai_type', 'security_analytics_insights', ['insight_type'], unique=False, schema='sentinel')
    op.create_index('ix_sai_severity', 'security_analytics_insights', ['severity'], unique=False, schema='sentinel')

    # 6. security_reports
    op.create_table(
        'security_reports',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('report_number', sa.String(length=64), nullable=False),
        sa.Column('report_type', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('period_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('period_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('generated_by_user_id', sa.String(length=128), nullable=False),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('canonical_manifest_json', sa.JSON(), nullable=False),
        sa.Column('report_hash', sa.String(length=64), nullable=False),
        sa.Column('integrity_status', sa.String(length=32), nullable=False),
        sa.Column('ledger_reference', sa.String(length=128), nullable=True),
        sa.Column('merkle_reference', sa.String(length=128), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('report_number'),
        schema='sentinel'
    )
    op.create_index('ix_sr_report_number', 'security_reports', ['report_number'], unique=True, schema='sentinel')
    op.create_index('ix_sr_report_type', 'security_reports', ['report_type'], unique=False, schema='sentinel')
    op.create_index('ix_sr_status', 'security_reports', ['status'], unique=False, schema='sentinel')

    # 7. security_report_sections
    op.create_table(
        'security_report_sections',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('report_id', sa.String(length=64), nullable=False),
        sa.Column('section_order', sa.Integer(), nullable=False),
        sa.Column('section_type', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('content_json', sa.JSON(), nullable=False),
        sa.Column('source_references_json', sa.JSON(), nullable=False),
        sa.Column('section_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['report_id'], ['sentinel.security_reports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('report_id', 'section_order', name='uq_report_section_order'),
        schema='sentinel'
    )
    op.create_index('ix_srs_report_id', 'security_report_sections', ['report_id'], unique=False, schema='sentinel')
    op.create_index('ix_srs_section_order', 'security_report_sections', ['section_order'], unique=False, schema='sentinel')

    # 8. security_evidence_packages
    op.create_table(
        'security_evidence_packages',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('package_number', sa.String(length=64), nullable=False),
        sa.Column('package_type', sa.String(length=64), nullable=False),
        sa.Column('scope', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('artifact_count', sa.Integer(), nullable=False),
        sa.Column('manifest_json', sa.JSON(), nullable=False),
        sa.Column('manifest_hash', sa.String(length=64), nullable=False),
        sa.Column('integrity_status', sa.String(length=32), nullable=False),
        sa.Column('ledger_reference', sa.String(length=128), nullable=True),
        sa.Column('merkle_reference', sa.String(length=128), nullable=True),
        sa.Column('created_by_user_id', sa.String(length=128), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('package_number'),
        schema='sentinel'
    )
    op.create_index('ix_sep_package_number', 'security_evidence_packages', ['package_number'], unique=True, schema='sentinel')
    op.create_index('ix_sep_package_type', 'security_evidence_packages', ['package_type'], unique=False, schema='sentinel')
    op.create_index('ix_sep_created_at', 'security_evidence_packages', ['created_at'], unique=False, schema='sentinel')

    # 9. evidence_package_artifacts
    op.create_table(
        'evidence_package_artifacts',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('package_id', sa.String(length=64), nullable=False),
        sa.Column('artifact_domain', sa.String(length=64), nullable=False),
        sa.Column('artifact_type', sa.String(length=64), nullable=False),
        sa.Column('artifact_id', sa.String(length=128), nullable=False),
        sa.Column('artifact_hash', sa.String(length=64), nullable=False),
        sa.Column('source_reference', sa.String(length=255), nullable=False),
        sa.Column('binding_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['package_id'], ['sentinel.security_evidence_packages.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('package_id', 'artifact_domain', 'artifact_id', name='uq_package_artifact_domain_id'),
        schema='sentinel'
    )
    op.create_index('ix_epa_package_id', 'evidence_package_artifacts', ['package_id'], unique=False, schema='sentinel')
    op.create_index('ix_epa_domain', 'evidence_package_artifacts', ['artifact_domain'], unique=False, schema='sentinel')
    op.create_index('ix_epa_artifact_id', 'evidence_package_artifacts', ['artifact_id'], unique=False, schema='sentinel')

    # 10. security_analytics_provenance_records
    op.create_table(
        'security_analytics_provenance_records',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('snapshot_id', sa.String(length=64), nullable=False),
        sa.Column('stage_number', sa.Integer(), nullable=False),
        sa.Column('stage_name', sa.String(length=64), nullable=False),
        sa.Column('artifact_type', sa.String(length=64), nullable=False),
        sa.Column('artifact_id', sa.String(length=128), nullable=False),
        sa.Column('artifact_hash', sa.String(length=64), nullable=False),
        sa.Column('previous_hash', sa.String(length=64), nullable=False),
        sa.Column('current_hash', sa.String(length=64), nullable=False),
        sa.Column('verification_status', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['snapshot_id'], ['sentinel.security_analytics_snapshots.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('snapshot_id', 'stage_number', name='uq_snapshot_provenance_stage_number'),
        schema='sentinel'
    )
    op.create_index('ix_sapr_snapshot_id', 'security_analytics_provenance_records', ['snapshot_id'], unique=False, schema='sentinel')
    op.create_index('ix_sapr_stage_number', 'security_analytics_provenance_records', ['stage_number'], unique=False, schema='sentinel')


def downgrade() -> None:
    op.drop_table('security_analytics_provenance_records', schema='sentinel')
    op.drop_table('evidence_package_artifacts', schema='sentinel')
    op.drop_table('security_evidence_packages', schema='sentinel')
    op.drop_table('security_report_sections', schema='sentinel')
    op.drop_table('security_reports', schema='sentinel')
    op.drop_table('security_analytics_insights', schema='sentinel')
    op.drop_table('security_trend_snapshots', schema='sentinel')
    op.drop_table('security_metric_evaluations', schema='sentinel')
    op.drop_table('security_metric_definitions', schema='sentinel')
    op.drop_table('security_analytics_snapshots', schema='sentinel')
