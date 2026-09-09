"""create_governance_ledger_table

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-09-06 23:45:00.000000

Sprint 5A — Cryptographic Governance Ledger Foundation.
Creates:
- sentinel.governance_ledger: Append-only cryptographically chained audit ledger
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.governance_ledger table
    op.create_table(
        "governance_ledger",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ledger_entry_id", sa.String(length=64), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=True),
        sa.Column("actor_username", sa.String(length=64), nullable=True),
        sa.Column("payload", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_governance_ledger"),
        sa.UniqueConstraint("ledger_entry_id", name="uq_governance_ledger_entry_id"),
        sa.UniqueConstraint("sequence_number", name="uq_governance_ledger_sequence_number"),
        schema="sentinel",
    )

    # 2. Indexes
    op.create_index(
        "ix_governance_ledger_entry_id",
        "governance_ledger",
        ["ledger_entry_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_governance_ledger_sequence_number",
        "governance_ledger",
        ["sequence_number"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_governance_ledger_event_type",
        "governance_ledger",
        ["event_type"],
        schema="sentinel",
    )
    op.create_index(
        "ix_governance_ledger_actor_id",
        "governance_ledger",
        ["actor_id"],
        schema="sentinel",
    )
    op.create_index(
        "ix_governance_ledger_entry_hash",
        "governance_ledger",
        ["entry_hash"],
        schema="sentinel",
    )
    op.create_index(
        "ix_governance_ledger_created_at",
        "governance_ledger",
        ["created_at"],
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_index("ix_governance_ledger_created_at", table_name="governance_ledger", schema="sentinel")
    op.drop_index("ix_governance_ledger_entry_hash", table_name="governance_ledger", schema="sentinel")
    op.drop_index("ix_governance_ledger_actor_id", table_name="governance_ledger", schema="sentinel")
    op.drop_index("ix_governance_ledger_event_type", table_name="governance_ledger", schema="sentinel")
    op.drop_index("ix_governance_ledger_sequence_number", table_name="governance_ledger", schema="sentinel")
    op.drop_index("ix_governance_ledger_entry_id", table_name="governance_ledger", schema="sentinel")
    op.drop_table("governance_ledger", schema="sentinel")
