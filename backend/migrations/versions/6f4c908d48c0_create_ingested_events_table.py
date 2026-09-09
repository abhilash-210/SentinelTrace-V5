"""create_ingested_events_table

Revision ID: 6f4c908d48c0
Revises: 
Create Date: 2026-09-06 12:16:23.069171

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '6f4c908d48c0'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create schema if not exists
    op.execute("CREATE SCHEMA IF NOT EXISTS sentinel;")

    # Create ingested_events table
    op.create_table(
        'ingested_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Internal database surrogate key'),
        sa.Column('event_id', sa.String(length=64), nullable=False, comment='Unique traceable event identifier'),
        sa.Column('source_name', sa.String(length=255), nullable=False, comment='Source system or reporting device name'),
        sa.Column('source_type', sa.String(length=100), nullable=False, comment='Category of event source'),
        sa.Column('file_format', sa.String(length=50), server_default='text', nullable=False, comment='Payload format'),
        sa.Column('raw_content', sa.Text(), nullable=False, comment='Exact unaltered raw event payload'),
        sa.Column('raw_content_hash', sa.String(length=64), nullable=False, comment='Cryptographic SHA-256 fingerprint'),
        sa.Column('content_size', sa.Integer(), server_default='0', nullable=False, comment='Size of raw_content in bytes'),
        sa.Column('ingested_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False, comment='UTC timestamp'),
        sa.Column('processing_status', sa.String(length=50), server_default='PRESERVED', nullable=False, comment='Integrity state'),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False, comment='Contextual metadata'),
        sa.PrimaryKeyConstraint('id'),
        schema='sentinel'
    )
    op.create_index('ix_ingested_events_event_id', 'ingested_events', ['event_id'], unique=True, schema='sentinel')
    op.create_index('ix_ingested_events_ingested_at', 'ingested_events', ['ingested_at'], unique=False, schema='sentinel')
    op.create_index('ix_ingested_events_source_name', 'ingested_events', ['source_name'], unique=False, schema='sentinel')
    op.create_index('ix_ingested_events_source_type', 'ingested_events', ['source_type'], unique=False, schema='sentinel')


def downgrade() -> None:
    op.drop_index('ix_ingested_events_source_type', table_name='ingested_events', schema='sentinel')
    op.drop_index('ix_ingested_events_source_name', table_name='ingested_events', schema='sentinel')
    op.drop_index('ix_ingested_events_ingested_at', table_name='ingested_events', schema='sentinel')
    op.drop_index('ix_ingested_events_event_id', table_name='ingested_events', schema='sentinel')
    op.drop_table('ingested_events', schema='sentinel')
