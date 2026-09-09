"""
services/merkle_batch_service.py
--------------------------------
Service for creating, persisting, querying, and tracing sealed Merkle batches and proofs.

Sprint 5B — Merkle Tree Proofs & Independent Auditor Verification.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.ledger import GovernanceLedgerEntry
from app.models.merkle import MerkleBatch, MerkleProof
from app.services.merkle_tree_service import MerkleTreeService

logger = logging.getLogger("sentinel.services.merkle_batch")


class MerkleBatchService:
    """Manages lifecycle, persistence, and querying of Merkle Batches and Inclusion Proofs."""

    @classmethod
    def create_batch_from_ledger(
        cls,
        db: Session,
        limit: int = 50,
        custom_batch_ref: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creates and seals a deterministic Merkle batch from unbatched governance ledger entries.

        Deterministic ordering applied:
        1. sequence_number ASC
        2. created_at ASC
        3. ledger_entry_id ASC
        """
        # Find entries already in a batch to avoid duplicating inclusion in multiple active batches
        existing_proofs = db.query(MerkleProof.ledger_entry_id).all()
        batched_entry_ids = {row[0] for row in existing_proofs}

        # Query eligible ledger entries with strict deterministic ordering
        query = (
            db.query(GovernanceLedgerEntry)
            .order_by(
                GovernanceLedgerEntry.sequence_number.asc(),
                GovernanceLedgerEntry.created_at.asc(),
                GovernanceLedgerEntry.ledger_entry_id.asc(),
            )
        )

        all_entries = query.all()
        eligible_entries = [e for e in all_entries if e.ledger_entry_id not in batched_entry_ids]

        if not eligible_entries:
            # If all entries are already batched, we check if there are any ledger entries at all
            if not all_entries:
                raise ValueError("No governance ledger entries found to create a Merkle batch.")
            else:
                # If all entries are already in batches, allow creating a snapshot batch over all ledger entries
                # or raise an informative notice.
                eligible_entries = all_entries[:limit]

        batch_entries = eligible_entries[:limit]
        entry_count = len(batch_entries)

        # Extract entry hashes
        entry_hashes = [entry.entry_hash for entry in batch_entries]
        seq_start = batch_entries[0].sequence_number
        seq_end = batch_entries[-1].sequence_number

        batch_ref = custom_batch_ref or f"ledger_seq_{seq_start}_to_{seq_end}"
        batch_id = f"mrb_{uuid.uuid4().hex[:12]}"

        # Build Merkle Tree
        merkle_root, tree_levels, proofs = MerkleTreeService.build_tree(entry_hashes)

        if not merkle_root:
            raise ValueError("Failed to compute Merkle root from ledger entries.")

        now_utc = datetime.now(timezone.utc)

        # 1. Create sealed batch record
        merkle_batch = MerkleBatch(
            batch_id=batch_id,
            ledger_batch_reference=batch_ref,
            entry_count=entry_count,
            tree_version="v1",
            merkle_root=merkle_root,
            root_algorithm="SHA256",
            ordering_strategy="SEQUENCE_ASC_CREATED_ASC_ID_ASC",
            tree_status="SEALED",
            created_at=now_utc,
            sealed_at=now_utc,
        )
        db.add(merkle_batch)

        # 2. Store inclusion proof for every entry in the batch
        created_proofs: List[MerkleProof] = []
        for idx, entry in enumerate(batch_entries):
            leaf_hash = MerkleTreeService.generate_leaf_hash(entry.entry_hash)
            proof_path = proofs[idx]
            proof_record = MerkleProof(
                proof_id=f"mrp_{uuid.uuid4().hex[:12]}",
                batch_id=batch_id,
                ledger_entry_id=entry.ledger_entry_id,
                leaf_hash=leaf_hash,
                proof_path=proof_path,
                proof_depth=len(proof_path),
                tree_version="v1",
                created_at=now_utc,
            )
            db.add(proof_record)
            created_proofs.append(proof_record)

        db.commit()
        db.refresh(merkle_batch)

        logger.info(
            f"Sealed Merkle Batch '{batch_id}' with {entry_count} entries. Root: {merkle_root[:16]}..."
        )

        return merkle_batch.to_dict()

    @classmethod
    def get_batches(
        cls,
        db: Session,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List Merkle batches ordered by newest first."""
        batches = (
            db.query(MerkleBatch)
            .order_by(desc(MerkleBatch.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [b.to_dict() for b in batches]

    @classmethod
    def get_batch_by_id(cls, db: Session, batch_id: str) -> Optional[Dict[str, Any]]:
        """Get batch details by batch_id."""
        batch = db.query(MerkleBatch).filter(MerkleBatch.batch_id == batch_id).first()
        if not batch:
            return None
        return batch.to_dict()

    @classmethod
    def get_proof_by_ledger_entry_id(
        cls, db: Session, ledger_entry_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve the cryptographic inclusion proof for a ledger entry."""
        proof = (
            db.query(MerkleProof)
            .filter(MerkleProof.ledger_entry_id == ledger_entry_id)
            .order_by(desc(MerkleProof.created_at))
            .first()
        )
        if not proof:
            return None

        # Fetch associated batch to supply merkle_root for convenience
        batch = db.query(MerkleBatch).filter(MerkleBatch.batch_id == proof.batch_id).first()

        data = proof.to_dict()
        data["merkle_root"] = batch.merkle_root if batch else None
        return data

    @classmethod
    def get_batch_trace(cls, db: Session, batch_id: str) -> Optional[Dict[str, Any]]:
        """
        Generate complete cryptographic provenance trace for a Merkle batch.
        Demonstrates: Ledger Entry -> Ledger Hash -> Merkle Leaf -> Sibling Proof Path -> Merkle Root.
        """
        batch = db.query(MerkleBatch).filter(MerkleBatch.batch_id == batch_id).first()
        if not batch:
            return None

        proofs = (
            db.query(MerkleProof)
            .filter(MerkleProof.batch_id == batch_id)
            .order_by(MerkleProof.created_at.asc(), MerkleProof.id.asc())
            .all()
        )

        entries_trace = []
        max_depth = 0

        for p in proofs:
            ledger_entry = (
                db.query(GovernanceLedgerEntry)
                .filter(GovernanceLedgerEntry.ledger_entry_id == p.ledger_entry_id)
                .first()
            )

            # Perform local verification check
            verification = MerkleTreeService.verify_inclusion_proof(
                leaf_hash=p.leaf_hash,
                proof_path=p.proof_path,
                merkle_root=batch.merkle_root,
            )

            depth = p.proof_depth or len(p.proof_path)
            if depth > max_depth:
                max_depth = depth

            entries_trace.append(
                {
                    "ledger_entry_id": p.ledger_entry_id,
                    "sequence_number": ledger_entry.sequence_number if ledger_entry else 0,
                    "event_type": ledger_entry.event_type if ledger_entry else "UNKNOWN",
                    "ledger_entry_hash": ledger_entry.entry_hash if ledger_entry else "",
                    "merkle_leaf_hash": p.leaf_hash,
                    "proof_depth": depth,
                    "verification_status": verification.get("verification_status", "UNKNOWN"),
                }
            )

        return {
            "batch_id": batch.batch_id,
            "merkle_root": batch.merkle_root,
            "tree_version": batch.tree_version,
            "tree_status": batch.tree_status,
            "entry_count": batch.entry_count,
            "tree_depth": max_depth,
            "ordering_strategy": batch.ordering_strategy,
            "entries": entries_trace,
        }
