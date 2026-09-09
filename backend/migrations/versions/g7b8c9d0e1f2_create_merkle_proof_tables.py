"""create_merkle_proof_tables

Revision ID: g7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-09-06 23:55:00.000000

Sprint 5B — Merkle Tree Proofs & Independent Auditor Verification.
Creates:
- sentinel.merkle_batches: Sealed Merkle root batches over immutable ledger records
- sentinel.merkle_proofs: Cryptographic inclusion proofs for independent verification
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = "g7b8c9d0e1f2"
down_revision: Union[str, None] = "f6a7b8c9d0e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create sentinel.merkle_batches table
    op.create_table(
        "merkle_batches",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("batch_id", sa.String(length=64), nullable=False),
        sa.Column("ledger_batch_reference", sa.String(length=64), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False, default=0),
        sa.Column("tree_version", sa.String(length=32), nullable=False, default="v1"),
        sa.Column("merkle_root", sa.String(length=64), nullable=False),
        sa.Column("root_algorithm", sa.String(length=32), nullable=False, default="SHA256"),
        sa.Column("ordering_strategy", sa.String(length=64), nullable=False, default="SEQUENCE_ASC_CREATED_ASC_ID_ASC"),
        sa.Column("tree_status", sa.String(length=32), nullable=False, default="SEALED"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_merkle_batches"),
        sa.UniqueConstraint("batch_id", name="uq_merkle_batches_batch_id"),
        schema="sentinel",
    )

    op.create_index(
        "ix_merkle_batches_batch_id",
        "merkle_batches",
        ["batch_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_merkle_batches_ledger_batch_reference",
        "merkle_batches",
        ["ledger_batch_reference"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_merkle_batches_merkle_root",
        "merkle_batches",
        ["merkle_root"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_merkle_batches_created_at",
        "merkle_batches",
        ["created_at"],
        unique=False,
        schema="sentinel",
    )

    # 2. Create sentinel.merkle_proofs table
    op.create_table(
        "merkle_proofs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("proof_id", sa.String(length=64), nullable=False),
        sa.Column("batch_id", sa.String(length=64), nullable=False),
        sa.Column("ledger_entry_id", sa.String(length=64), nullable=False),
        sa.Column("leaf_hash", sa.String(length=64), nullable=False),
        sa.Column("proof_path", JSONB().with_variant(JSON(), "sqlite"), nullable=False),
        sa.Column("proof_depth", sa.Integer(), nullable=False, default=0),
        sa.Column("tree_version", sa.String(length=32), nullable=False, default="v1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_merkle_proofs"),
        sa.UniqueConstraint("proof_id", name="uq_merkle_proofs_proof_id"),
        schema="sentinel",
    )

    op.create_index(
        "ix_merkle_proofs_proof_id",
        "merkle_proofs",
        ["proof_id"],
        unique=True,
        schema="sentinel",
    )
    op.create_index(
        "ix_merkle_proofs_batch_id",
        "merkle_proofs",
        ["batch_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_merkle_proofs_ledger_entry_id",
        "merkle_proofs",
        ["ledger_entry_id"],
        unique=False,
        schema="sentinel",
    )
    op.create_index(
        "ix_merkle_proofs_created_at",
        "merkle_proofs",
        ["created_at"],
        unique=False,
        schema="sentinel",
    )


def downgrade() -> None:
    op.drop_index("ix_merkle_proofs_created_at", table_name="merkle_proofs", schema="sentinel")
    op.drop_index("ix_merkle_proofs_ledger_entry_id", table_name="merkle_proofs", schema="sentinel")
    op.drop_index("ix_merkle_proofs_batch_id", table_name="merkle_proofs", schema="sentinel")
    op.drop_index("ix_merkle_proofs_proof_id", table_name="merkle_proofs", schema="sentinel")
    op.drop_table("merkle_proofs", schema="sentinel")

    op.drop_index("ix_merkle_batches_created_at", table_name="merkle_batches", schema="sentinel")
    op.drop_index("ix_merkle_batches_merkle_root", table_name="merkle_batches", schema="sentinel")
    op.drop_index("ix_merkle_batches_ledger_batch_reference", table_name="merkle_batches", schema="sentinel")
    op.drop_index("ix_merkle_batches_batch_id", table_name="merkle_batches", schema="sentinel")
    op.drop_table("merkle_batches", schema="sentinel")
