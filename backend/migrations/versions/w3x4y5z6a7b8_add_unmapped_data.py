"""add unmapped_data to normalized_events

Revision ID: w3x4y5z6a7b8
Revises: v2w3x4y5z6a7
Create Date: 2026-09-23 23:17:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "w3x4y5z6a7b8"
down_revision = "v2w3x4y5z6a7"
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Add unmapped_data column
    op.add_column("normalized_events", sa.Column("unmapped_data", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"), schema="sentinel")

def downgrade() -> None:
    # Drop unmapped_data column
    op.drop_column("normalized_events", "unmapped_data", schema="sentinel")
