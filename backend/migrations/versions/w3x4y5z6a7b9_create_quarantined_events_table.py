"""create quarantined_events table

Revision ID: w3x4y5z6a7b9
Revises: w3x4y5z6a7b8
Create Date: 2026-09-23 23:19:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "w3x4y5z6a7b9"
down_revision = "w3x4y5z6a7b8"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        "quarantined_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("quarantine_id", sa.String(length=64), nullable=False),
        sa.Column("source_name", sa.String(length=255), nullable=False),
        sa.Column("source_type", sa.String(length=100), nullable=False),
        sa.Column("raw_content", sa.Text(), nullable=False),
        sa.Column("failure_reason", sa.Text(), nullable=False),
        sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("quarantine_id"),
        schema="sentinel"
    )

def downgrade() -> None:
    op.drop_table("quarantined_events", schema="sentinel")
