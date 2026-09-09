"""create_normalization_tables

Revision ID: a1b2c3d4e5f6
Revises: 6f4c908d48c0
Create Date: 2026-09-06 12:35:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '6f4c908d48c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Source Profiles Table
    op.create_table(
        'source_profiles',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('source_profile_id', sa.String(length=64), nullable=False),
        sa.Column('profile_name', sa.String(length=255), nullable=False),
        sa.Column('source_type', sa.String(length=100), nullable=False),
        sa.Column('supported_format', sa.String(length=50), nullable=False),
        sa.Column('parser_type', sa.String(length=50), nullable=False),
        sa.Column('version', sa.String(length=32), server_default='v1.0.0', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('configuration', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_source_profiles_source_profile_id', 'source_profiles', ['source_profile_id'], unique=True, schema='sentinel')
    op.create_index('ix_source_profiles_source_type', 'source_profiles', ['source_type'], unique=False, schema='sentinel')

    # 2. Normalized Events Table
    op.create_table(
        'normalized_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('normalized_event_id', sa.String(length=64), nullable=False),
        sa.Column('original_event_id', sa.String(length=64), nullable=False),
        sa.Column('class_uid', sa.Integer(), server_default='0', nullable=False),
        sa.Column('class_name', sa.String(length=100), nullable=False),
        sa.Column('activity_id', sa.Integer(), server_default='0', nullable=False),
        sa.Column('activity_name', sa.String(length=100), nullable=False),
        sa.Column('event_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('source_name', sa.String(length=255), nullable=False),
        sa.Column('source_type', sa.String(length=100), nullable=False),
        sa.Column('action', sa.String(length=50), nullable=True),
        sa.Column('src_ip', sa.String(length=45), nullable=True),
        sa.Column('src_port', sa.Integer(), nullable=True),
        sa.Column('dst_ip', sa.String(length=45), nullable=True),
        sa.Column('dst_port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(length=30), nullable=True),
        sa.Column('severity', sa.String(length=30), nullable=True),
        sa.Column('user_name', sa.String(length=255), nullable=True),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('process_name', sa.String(length=255), nullable=True),
        sa.Column('process_id', sa.Integer(), nullable=True),
        sa.Column('raw_data', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
        sa.Column('parser_name', sa.String(length=100), nullable=False),
        sa.Column('parser_version', sa.String(length=32), server_default='1.0.0', nullable=False),
        sa.Column('source_profile_id', sa.String(length=64), nullable=True),
        sa.Column('normalization_status', sa.String(length=50), server_default='NORMALIZED', nullable=False),
        sa.Column('normalization_confidence', sa.Float(), server_default='1.0', nullable=False),
        sa.Column('confidence_reasons', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('normalized_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_normalized_events_normalized_id', 'normalized_events', ['normalized_event_id'], unique=True, schema='sentinel')
    op.create_index('ix_normalized_events_original_id', 'normalized_events', ['original_event_id'], unique=False, schema='sentinel')
    op.create_index('ix_normalized_events_class_name', 'normalized_events', ['class_name'], unique=False, schema='sentinel')
    op.create_index('ix_normalized_events_status', 'normalized_events', ['normalization_status'], unique=False, schema='sentinel')
    op.create_index('ix_normalized_events_normalized_at', 'normalized_events', ['normalized_at'], unique=False, schema='sentinel')


def downgrade() -> None:
    op.drop_index('ix_normalized_events_normalized_at', table_name='normalized_events', schema='sentinel')
    op.drop_index('ix_normalized_events_status', table_name='normalized_events', schema='sentinel')
    op.drop_index('ix_normalized_events_class_name', table_name='normalized_events', schema='sentinel')
    op.drop_index('ix_normalized_events_original_id', table_name='normalized_events', schema='sentinel')
    op.drop_index('ix_normalized_events_normalized_id', table_name='normalized_events', schema='sentinel')
    op.drop_table('normalized_events', schema='sentinel')

    op.drop_index('ix_source_profiles_source_type', table_name='source_profiles', schema='sentinel')
    op.drop_index('ix_source_profiles_source_profile_id', table_name='source_profiles', schema='sentinel')
    op.drop_table('source_profiles', schema='sentinel')
