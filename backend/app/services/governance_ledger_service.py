"""
services/governance_ledger_service.py
-------------------------------------
Cryptographic Governance Ledger Service for SentinelTrace V5.

Sprint 5A — Cryptographic Governance Ledger Foundation.
Provides:
- Deterministic canonical JSON serialization
- SHA-256 Payload and Entry Hash generation
- Sequential hash-chaining: H_n = SHA256(seq | H_{n-1} | payload_hash)
- Full cryptographic chain verification & tamper detection
"""

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.ledger import GovernanceLedgerEntry

logger = logging.getLogger("sentinel.services.ledger")

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


class GovernanceLedgerService:
    """Service for managing and cryptographically verifying the governance ledger."""

    GENESIS_HASH = GENESIS_HASH

    @staticmethod
    def canonicalize_payload(payload: Any) -> str:
        """
        Produces deterministic, canonical JSON representation of any payload.
        Ensures identical SHA-256 hash regardless of dictionary insertion order.
        """
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )

    @classmethod
    def calculate_payload_hash(cls, payload: Any) -> str:
        """Calculates SHA-256 hash of canonicalized UTF-8 payload."""
        canonical_str = cls.canonicalize_payload(payload)
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    @staticmethod
    def calculate_entry_hash(
        sequence_number: int,
        previous_hash: str,
        payload_hash: str,
    ) -> str:
        """
        Calculates cryptographic entry hash:
        entry_hash = SHA256(f"{sequence_number}|{previous_hash}|{payload_hash}")
        """
        chain_input = f"{sequence_number}|{previous_hash}|{payload_hash}"
        return hashlib.sha256(chain_input.encode("utf-8")).hexdigest()

    @classmethod
    def append_entry(
        cls,
        db: Session,
        event_type: str,
        actor_id: Optional[str],
        actor_username: Optional[str],
        payload: Dict[str, Any],
    ) -> GovernanceLedgerEntry:
        """
        Appends a new cryptographically chained entry to the governance ledger.
        Atomic and sequential.
        """
        last_entry = (
            db.query(GovernanceLedgerEntry)
            .order_by(desc(GovernanceLedgerEntry.sequence_number))
            .first()
        )

        if last_entry is None:
            sequence_number = 1
            previous_hash = cls.GENESIS_HASH
        else:
            sequence_number = last_entry.sequence_number + 1
            previous_hash = last_entry.entry_hash

        payload_hash = cls.calculate_payload_hash(payload)
        entry_hash = cls.calculate_entry_hash(
            sequence_number=sequence_number,
            previous_hash=previous_hash,
            payload_hash=payload_hash,
        )

        new_entry = GovernanceLedgerEntry(
            sequence_number=sequence_number,
            event_type=event_type,
            actor_id=actor_id,
            actor_username=actor_username,
            payload=payload,
            payload_hash=payload_hash,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )
        db.add(new_entry)
        db.flush()

        logger.info(
            f"Governance Ledger [#{sequence_number}] {event_type} appended by '{actor_username}' "
            f"(Hash: {entry_hash[:12]}...)"
        )
        return new_entry

    @classmethod
    def verify_chain(cls, db: Session) -> Dict[str, Any]:
        """
        Traverses the entire ledger from Genesis (sequence 1) to head.
        Verifies:
        1. Continuous sequence numbers
        2. Previous hash linkage
        3. Payload hash integrity
        4. Entry hash calculation
        """
        entries = (
            db.query(GovernanceLedgerEntry)
            .order_by(GovernanceLedgerEntry.sequence_number.asc())
            .all()
        )

        total_entries = len(entries)
        if total_entries == 0:
            return {
                "status": "VERIFIED",
                "entries_checked": 0,
                "chain_head": cls.GENESIS_HASH,
                "first_invalid_entry": None,
                "sequence_number": None,
                "reason": "Ledger is empty (Genesis state)",
            }

        for idx, entry in enumerate(entries):
            expected_seq = idx + 1
            if entry.sequence_number != expected_seq:
                return {
                    "status": "TAMPER_DETECTED",
                    "entries_checked": idx,
                    "chain_head": None,
                    "first_invalid_entry": entry.ledger_entry_id,
                    "sequence_number": entry.sequence_number,
                    "reason": f"Sequence number gap/disorder: expected {expected_seq}, found {entry.sequence_number}",
                }

            # Linkage check
            if idx == 0:
                expected_prev = cls.GENESIS_HASH
            else:
                expected_prev = entries[idx - 1].entry_hash

            if entry.previous_hash != expected_prev:
                return {
                    "status": "TAMPER_DETECTED",
                    "entries_checked": idx,
                    "chain_head": None,
                    "first_invalid_entry": entry.ledger_entry_id,
                    "sequence_number": entry.sequence_number,
                    "reason": f"Broken previous_hash link: expected '{expected_prev}', found '{entry.previous_hash}'",
                }

            # Payload hash check
            recomputed_payload_hash = cls.calculate_payload_hash(entry.payload)
            if entry.payload_hash != recomputed_payload_hash:
                return {
                    "status": "TAMPER_DETECTED",
                    "entries_checked": idx,
                    "chain_head": None,
                    "first_invalid_entry": entry.ledger_entry_id,
                    "sequence_number": entry.sequence_number,
                    "reason": f"Payload hash mismatch: recalculated '{recomputed_payload_hash}', stored '{entry.payload_hash}'",
                }

            # Entry hash check
            recomputed_entry_hash = cls.calculate_entry_hash(
                sequence_number=entry.sequence_number,
                previous_hash=entry.previous_hash,
                payload_hash=entry.payload_hash,
            )
            if entry.entry_hash != recomputed_entry_hash:
                return {
                    "status": "TAMPER_DETECTED",
                    "entries_checked": idx,
                    "chain_head": None,
                    "first_invalid_entry": entry.ledger_entry_id,
                    "sequence_number": entry.sequence_number,
                    "reason": f"Entry hash mismatch: recalculated '{recomputed_entry_hash}', stored '{entry.entry_hash}'",
                }

        chain_head = entries[-1].entry_hash
        return {
            "status": "VERIFIED",
            "entries_checked": total_entries,
            "chain_head": chain_head,
            "first_invalid_entry": None,
            "sequence_number": entries[-1].sequence_number,
            "reason": "All entries verified cryptographically against SHA-256 chain formula",
        }

    @staticmethod
    def get_chain_head(db: Session) -> Optional[Dict[str, Any]]:
        """Retrieves latest block/entry at the head of the chain."""
        entry = (
            db.query(GovernanceLedgerEntry)
            .order_by(desc(GovernanceLedgerEntry.sequence_number))
            .first()
        )
        return entry.to_dict() if entry else None

    @staticmethod
    def get_entries(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        event_type: Optional[str] = None,
        actor_id: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Retrieves paginated ledger entries with optional filtering."""
        query = db.query(GovernanceLedgerEntry)
        if event_type:
            query = query.filter(GovernanceLedgerEntry.event_type == event_type)
        if actor_id:
            query = query.filter(GovernanceLedgerEntry.actor_id == actor_id)

        total = query.count()
        entries = (
            query.order_by(desc(GovernanceLedgerEntry.sequence_number))
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [e.to_dict() for e in entries], total

    @staticmethod
    def get_entry_by_id(
        db: Session,
        ledger_entry_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Retrieves a single ledger entry by its unique ID."""
        entry = (
            db.query(GovernanceLedgerEntry)
            .filter(GovernanceLedgerEntry.ledger_entry_id == ledger_entry_id)
            .first()
        )
        return entry.to_dict() if entry else None
