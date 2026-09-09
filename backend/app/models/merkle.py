"""
models/merkle.py
----------------
SQLAlchemy models for Merkle Tree Batches and Cryptographic Inclusion Proofs.

Sprint 5B — Merkle Tree Proofs & Independent Auditor Verification.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

from app.database import Base


class MerkleBatch(Base):
    """
    Sealed batch of governance ledger entries anchored by a deterministic Merkle Root.

    Status lifecycle:
    - BUILDING: Batch is assembling entries
    - SEALED: Batch is finalized, root is cryptographically locked and immutable
    - VERIFIED: All leaf proofs within the batch have been verified
    - INVALID: Tampering detected within batch records
    """

    __tablename__ = "merkle_batches"
    __table_args__ = {"schema": "sentinel"}

    id = Column(Integer, primary_key=True, index=True)
    batch_id = Column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: f"mrb_{uuid.uuid4().hex[:12]}",
    )
    ledger_batch_reference = Column(String(64), nullable=False, index=True)
    entry_count = Column(Integer, nullable=False, default=0)
    tree_version = Column(String(32), nullable=False, default="v1")
    merkle_root = Column(String(64), nullable=False, index=True)
    root_algorithm = Column(String(32), nullable=False, default="SHA256")
    ordering_strategy = Column(
        String(64),
        nullable=False,
        default="SEQUENCE_ASC_CREATED_ASC_ID_ASC",
    )
    tree_status = Column(String(32), nullable=False, default="SEALED")
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        index=True,
    )
    sealed_at = Column(
        DateTime(timezone=True),
        nullable=True,
        default=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert batch to serializable dictionary."""
        return {
            "id": self.id,
            "batch_id": self.batch_id,
            "ledger_batch_reference": self.ledger_batch_reference,
            "entry_count": self.entry_count,
            "tree_version": self.tree_version,
            "merkle_root": self.merkle_root,
            "root_algorithm": self.root_algorithm,
            "ordering_strategy": self.ordering_strategy,
            "tree_status": self.tree_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "sealed_at": self.sealed_at.isoformat() if self.sealed_at else None,
        }


class MerkleProof(Base):
    """
    Cryptographic inclusion proof linking an individual ledger entry to a sealed Merkle batch root.
    """

    __tablename__ = "merkle_proofs"
    __table_args__ = {"schema": "sentinel"}

    id = Column(Integer, primary_key=True, index=True)
    proof_id = Column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: f"mrp_{uuid.uuid4().hex[:12]}",
    )
    batch_id = Column(String(64), nullable=False, index=True)
    ledger_entry_id = Column(String(64), nullable=False, index=True)
    leaf_hash = Column(String(64), nullable=False)
    proof_path = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
    )
    proof_depth = Column(Integer, nullable=False, default=0)
    tree_version = Column(String(32), nullable=False, default="v1")
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        index=True,
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert proof to serializable dictionary."""
        return {
            "id": self.id,
            "proof_id": self.proof_id,
            "batch_id": self.batch_id,
            "ledger_entry_id": self.ledger_entry_id,
            "leaf_hash": self.leaf_hash,
            "proof_path": self.proof_path,
            "proof_depth": self.proof_depth,
            "tree_version": self.tree_version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
