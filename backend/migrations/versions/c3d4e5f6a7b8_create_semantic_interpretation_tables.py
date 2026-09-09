"""create_semantic_interpretation_tables

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-09-06 18:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Semantic Interpretations Table
    op.create_table(
        'semantic_interpretations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('interpretation_id', sa.String(length=64), nullable=False),
        sa.Column('normalized_event_id', sa.String(length=64), nullable=False),
        sa.Column('original_event_id', sa.String(length=64), nullable=False),
        sa.Column('policy_id', sa.String(length=64), nullable=True),
        sa.Column('policy_version', sa.Integer(), nullable=True),
        sa.Column('vendor_name', sa.String(length=255), nullable=False),
        sa.Column('source_profile_id', sa.String(length=64), nullable=False),
        sa.Column('source_field', sa.String(length=100), nullable=False),
        sa.Column('source_value', sa.String(length=255), nullable=False),
        sa.Column('canonical_field', sa.String(length=100), nullable=False),
        sa.Column('interpreted_value', sa.String(length=255), nullable=True),
        sa.Column('equivalence_classification', sa.String(length=32), nullable=True),
        sa.Column('risk_level', sa.String(length=32), server_default='LOW', nullable=False),
        sa.Column('interpretation_status', sa.String(length=32), server_default='INTERPRETED', nullable=False),
        sa.Column('confidence_score', sa.Float(), server_default='1.0', nullable=False),
        sa.Column('confidence_reasons', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_semantic_interpretations_interpretation_id', 'semantic_interpretations', ['interpretation_id'], unique=True, schema='sentinel')
    op.create_index('ix_semantic_interpretations_normalized_event_id', 'semantic_interpretations', ['normalized_event_id'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_interpretations_original_event_id', 'semantic_interpretations', ['original_event_id'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_interpretations_policy_id', 'semantic_interpretations', ['policy_id'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_interpretations_status', 'semantic_interpretations', ['interpretation_status'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_interpretations_risk_level', 'semantic_interpretations', ['risk_level'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_interpretations_created_at', 'semantic_interpretations', ['created_at'], unique=False, schema='sentinel')

    # 2. Semantic Drift Alerts Table
    op.create_table(
        'semantic_drift_alerts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('alert_id', sa.String(length=64), nullable=False),
        sa.Column('normalized_event_id', sa.String(length=64), nullable=False),
        sa.Column('interpretation_id', sa.String(length=64), nullable=True),
        sa.Column('policy_id', sa.String(length=64), nullable=True),
        sa.Column('drift_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=32), server_default='MEDIUM', nullable=False),
        sa.Column('status', sa.String(length=32), server_default='OPEN', nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('expected_value', sa.String(length=255), nullable=True),
        sa.Column('observed_value', sa.String(length=255), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['interpretation_id'], ['sentinel.semantic_interpretations.interpretation_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_semantic_drift_alerts_alert_id', 'semantic_drift_alerts', ['alert_id'], unique=True, schema='sentinel')
    op.create_index('ix_semantic_drift_alerts_normalized_event_id', 'semantic_drift_alerts', ['normalized_event_id'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_drift_alerts_interpretation_id', 'semantic_drift_alerts', ['interpretation_id'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_drift_alerts_drift_type', 'semantic_drift_alerts', ['drift_type'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_drift_alerts_severity', 'semantic_drift_alerts', ['severity'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_drift_alerts_status', 'semantic_drift_alerts', ['status'], unique=False, schema='sentinel')
    op.create_index('ix_semantic_drift_alerts_detected_at', 'semantic_drift_alerts', ['detected_at'], unique=False, schema='sentinel')


def downgrade() -> None:
    op.drop_index('ix_semantic_drift_alerts_detected_at', table_name='semantic_drift_alerts', schema='sentinel')
    op.drop_index('ix_semantic_drift_alerts_status', table_name='semantic_drift_alerts', schema='sentinel')
    op.drop_index('ix_semantic_drift_alerts_severity', table_name='semantic_drift_alerts', schema='sentinel')
    op.drop_index('ix_semantic_drift_alerts_drift_type', table_name='semantic_drift_alerts', schema='sentinel')
    op.drop_index('ix_semantic_drift_alerts_interpretation_id', table_name='semantic_drift_alerts', schema='sentinel')
    op.drop_index('ix_semantic_drift_alerts_normalized_event_id', table_name='semantic_drift_alerts', schema='sentinel')
    op.drop_index('ix_semantic_drift_alerts_alert_id', table_name='semantic_drift_alerts', schema='sentinel')
    op.drop_table('semantic_drift_alerts', schema='sentinel')

    op.drop_index('ix_semantic_interpretations_created_at', table_name='semantic_interpretations', schema='sentinel')
    op.drop_index('ix_semantic_interpretations_risk_level', table_name='semantic_interpretations', schema='sentinel')
    op.drop_index('ix_semantic_interpretations_status', table_name='semantic_interpretations', schema='sentinel')
    op.drop_index('ix_semantic_interpretations_policy_id', table_name='semantic_interpretations', schema='sentinel')
    op.drop_index('ix_semantic_interpretations_original_event_id', table_name='semantic_interpretations', schema='sentinel')
    op.drop_index('ix_semantic_interpretations_normalized_event_id', table_name='semantic_interpretations', schema='sentinel')
    op.drop_index('ix_semantic_interpretations_interpretation_id', table_name='semantic_interpretations', schema='sentinel')
    op.drop_table('semantic_interpretations', schema='sentinel')
