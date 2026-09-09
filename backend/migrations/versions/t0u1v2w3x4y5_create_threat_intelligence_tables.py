"""create_threat_intelligence_tables

Revision ID: t0u1v2w3x4y5
Revises: s9t0u1v2w3x4
Create Date: 2026-09-08 22:00:00.000000

Sprint 11B: Threat Intelligence Integration, Adversary Context & Security Intelligence Correlation
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 't0u1v2w3x4y5'
down_revision: Union[str, None] = 's9t0u1v2w3x4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. threat_intelligence_sources
    op.create_table(
        'threat_intelligence_sources',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('source_name', sa.String(length=128), nullable=False),
        sa.Column('source_type', sa.String(length=64), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('provider', sa.String(length=128), nullable=False),
        sa.Column('trust_level', sa.String(length=64), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('last_ingested_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('source_name'),
        schema='sentinel'
    )
    op.create_index('ix_threat_source_type', 'threat_intelligence_sources', ['source_type'], unique=False, schema='sentinel')
    op.create_index('ix_threat_source_trust', 'threat_intelligence_sources', ['trust_level'], unique=False, schema='sentinel')

    # 2. threat_intelligence_artifacts
    op.create_table(
        'threat_intelligence_artifacts',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('artifact_reference', sa.String(length=128), nullable=False),
        sa.Column('source_id', sa.String(length=64), nullable=False),
        sa.Column('artifact_type', sa.String(length=64), nullable=False),
        sa.Column('raw_content_reference', sa.Text(), nullable=True),
        sa.Column('normalized_content', sa.JSON(), nullable=True),
        sa.Column('content_hash', sa.String(length=64), nullable=False),
        sa.Column('integrity_status', sa.String(length=32), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('trust_status', sa.String(length=32), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['source_id'], ['sentinel.threat_intelligence_sources.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('artifact_reference'),
        schema='sentinel'
    )
    op.create_index('ix_threat_artifact_ref', 'threat_intelligence_artifacts', ['artifact_reference'], unique=False, schema='sentinel')
    op.create_index('ix_threat_artifact_type', 'threat_intelligence_artifacts', ['artifact_type'], unique=False, schema='sentinel')
    op.create_index('ix_threat_artifact_trust', 'threat_intelligence_artifacts', ['trust_status'], unique=False, schema='sentinel')
    op.create_index('ix_threat_artifact_hash', 'threat_intelligence_artifacts', ['content_hash'], unique=False, schema='sentinel')

    # 3. threat_indicators
    op.create_table(
        'threat_indicators',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('indicator_value', sa.String(length=512), nullable=False),
        sa.Column('indicator_type', sa.String(length=64), nullable=False),
        sa.Column('normalized_value', sa.String(length=512), nullable=False),
        sa.Column('artifact_id', sa.String(length=64), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('indicator_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['artifact_id'], ['sentinel.threat_intelligence_artifacts.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_threat_indicator_type', 'threat_indicators', ['indicator_type'], unique=False, schema='sentinel')
    op.create_index('ix_threat_indicator_norm_val', 'threat_indicators', ['normalized_value'], unique=False, schema='sentinel')
    op.create_index('ix_threat_indicator_status', 'threat_indicators', ['status'], unique=False, schema='sentinel')
    op.create_index('ix_threat_indicator_hash', 'threat_indicators', ['indicator_hash'], unique=False, schema='sentinel')

    # 4. threat_actors
    op.create_table(
        'threat_actors',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('actor_name', sa.String(length=128), nullable=False),
        sa.Column('aliases', sa.JSON(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('motivation', sa.String(length=64), nullable=True),
        sa.Column('sophistication', sa.String(length=64), nullable=True),
        sa.Column('origin_context', sa.String(length=128), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('actor_name'),
        schema='sentinel'
    )
    op.create_index('ix_threat_actor_name', 'threat_actors', ['actor_name'], unique=False, schema='sentinel')
    op.create_index('ix_threat_actor_status', 'threat_actors', ['status'], unique=False, schema='sentinel')

    # 5. threat_campaigns
    op.create_table(
        'threat_campaigns',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('campaign_reference', sa.String(length=128), nullable=False),
        sa.Column('campaign_name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('actor_id', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('campaign_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['actor_id'], ['sentinel.threat_actors.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('campaign_reference'),
        schema='sentinel'
    )
    op.create_index('ix_threat_campaign_ref', 'threat_campaigns', ['campaign_reference'], unique=False, schema='sentinel')
    op.create_index('ix_threat_campaign_status', 'threat_campaigns', ['status'], unique=False, schema='sentinel')
    op.create_index('ix_threat_campaign_hash', 'threat_campaigns', ['campaign_hash'], unique=False, schema='sentinel')

    # 6. threat_actor_campaign_mappings
    op.create_table(
        'threat_actor_campaign_mappings',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('actor_id', sa.String(length=64), nullable=False),
        sa.Column('campaign_id', sa.String(length=64), nullable=False),
        sa.Column('relationship_type', sa.String(length=64), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['actor_id'], ['sentinel.threat_actors.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['campaign_id'], ['sentinel.threat_campaigns.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('actor_id', 'campaign_id', name='uq_actor_campaign_mapping'),
        schema='sentinel'
    )

    # 7. threat_mitre_mappings
    op.create_table(
        'threat_mitre_mappings',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('artifact_id', sa.String(length=64), nullable=True),
        sa.Column('indicator_id', sa.String(length=64), nullable=True),
        sa.Column('campaign_id', sa.String(length=64), nullable=True),
        sa.Column('tactic_id', sa.String(length=64), nullable=False),
        sa.Column('technique_id', sa.String(length=64), nullable=False),
        sa.Column('subtechnique_id', sa.String(length=64), nullable=True),
        sa.Column('mapping_confidence', sa.Float(), nullable=False),
        sa.Column('mapping_source', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['artifact_id'], ['sentinel.threat_intelligence_artifacts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['indicator_id'], ['sentinel.threat_indicators.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['campaign_id'], ['sentinel.threat_campaigns.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_threat_mitre_technique', 'threat_mitre_mappings', ['technique_id'], unique=False, schema='sentinel')
    op.create_index('ix_threat_mitre_tactic', 'threat_mitre_mappings', ['tactic_id'], unique=False, schema='sentinel')

    # 8. threat_intelligence_correlations
    op.create_table(
        'threat_intelligence_correlations',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('indicator_id', sa.String(length=64), nullable=False),
        sa.Column('artifact_id', sa.String(length=64), nullable=True),
        sa.Column('event_reference', sa.String(length=128), nullable=False),
        sa.Column('normalized_event_id', sa.String(length=64), nullable=True),
        sa.Column('correlation_type', sa.String(length=64), nullable=False),
        sa.Column('correlation_confidence', sa.Float(), nullable=False),
        sa.Column('match_strength', sa.Float(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('correlation_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['artifact_id'], ['sentinel.threat_intelligence_artifacts.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['indicator_id'], ['sentinel.threat_indicators.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_threat_corr_indicator', 'threat_intelligence_correlations', ['indicator_id'], unique=False, schema='sentinel')
    op.create_index('ix_threat_corr_event_ref', 'threat_intelligence_correlations', ['event_reference'], unique=False, schema='sentinel')
    op.create_index('ix_threat_corr_status', 'threat_intelligence_correlations', ['status'], unique=False, schema='sentinel')
    op.create_index('ix_threat_corr_hash', 'threat_intelligence_correlations', ['correlation_hash'], unique=False, schema='sentinel')

    # 9. threat_trust_evaluations
    op.create_table(
        'threat_trust_evaluations',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('artifact_id', sa.String(length=64), nullable=False),
        sa.Column('source_score', sa.Float(), nullable=False),
        sa.Column('freshness_score', sa.Float(), nullable=False),
        sa.Column('completeness_score', sa.Float(), nullable=False),
        sa.Column('cross_validation_score', sa.Float(), nullable=False),
        sa.Column('integrity_score', sa.Float(), nullable=False),
        sa.Column('final_trust_score', sa.Float(), nullable=False),
        sa.Column('trust_status', sa.String(length=32), nullable=False),
        sa.Column('deductions_json', sa.JSON(), nullable=False),
        sa.Column('evaluation_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['artifact_id'], ['sentinel.threat_intelligence_artifacts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_threat_trust_artifact', 'threat_trust_evaluations', ['artifact_id'], unique=False, schema='sentinel')
    op.create_index('ix_threat_trust_status', 'threat_trust_evaluations', ['trust_status'], unique=False, schema='sentinel')
    op.create_index('ix_threat_trust_hash', 'threat_trust_evaluations', ['evaluation_hash'], unique=False, schema='sentinel')

    # 10. threat_intelligence_insights
    op.create_table(
        'threat_intelligence_insights',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('insight_type', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('title', sa.String(length=256), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('related_artifact_id', sa.String(length=64), nullable=True),
        sa.Column('related_campaign_id', sa.String(length=64), nullable=True),
        sa.Column('related_actor_id', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['related_actor_id'], ['sentinel.threat_actors.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['related_artifact_id'], ['sentinel.threat_intelligence_artifacts.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['related_campaign_id'], ['sentinel.threat_campaigns.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_threat_insight_type', 'threat_intelligence_insights', ['insight_type'], unique=False, schema='sentinel')
    op.create_index('ix_threat_insight_sev', 'threat_intelligence_insights', ['severity'], unique=False, schema='sentinel')

    # 11. threat_provenance_records
    op.create_table(
        'threat_provenance_records',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('artifact_id', sa.String(length=64), nullable=False),
        sa.Column('provenance_stage', sa.String(length=128), nullable=False),
        sa.Column('stage_order', sa.Integer(), nullable=False),
        sa.Column('entity_type', sa.String(length=64), nullable=False),
        sa.Column('entity_reference', sa.String(length=128), nullable=False),
        sa.Column('previous_hash', sa.String(length=64), nullable=False),
        sa.Column('current_hash', sa.String(length=64), nullable=False),
        sa.Column('ledger_reference', sa.String(length=128), nullable=True),
        sa.Column('merkle_reference', sa.String(length=128), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_threat_prov_artifact', 'threat_provenance_records', ['artifact_id'], unique=False, schema='sentinel')
    op.create_index('ix_threat_prov_stage_order', 'threat_provenance_records', ['stage_order'], unique=False, schema='sentinel')
    op.create_index('ix_threat_prov_hash', 'threat_provenance_records', ['current_hash'], unique=False, schema='sentinel')


def downgrade() -> None:
    op.drop_table('threat_provenance_records', schema='sentinel')
    op.drop_table('threat_intelligence_insights', schema='sentinel')
    op.drop_table('threat_trust_evaluations', schema='sentinel')
    op.drop_table('threat_intelligence_correlations', schema='sentinel')
    op.drop_table('threat_mitre_mappings', schema='sentinel')
    op.drop_table('threat_actor_campaign_mappings', schema='sentinel')
    op.drop_table('threat_campaigns', schema='sentinel')
    op.drop_table('threat_actors', schema='sentinel')
    op.drop_table('threat_indicators', schema='sentinel')
    op.drop_table('threat_intelligence_artifacts', schema='sentinel')
    op.drop_table('threat_intelligence_sources', schema='sentinel')
