"""
models/ledger.py
----------------
SQLAlchemy model for the Cryptographic Governance Ledger.

Sprint 5A — Cryptographic Governance Ledger Foundation (Tamper-Evident Hash Chaining).
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import Column, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.database import Base


class GovernanceLedgerEntry(Base):
    """
    Append-only, cryptographically hash-chained governance ledger entry.

    Chain Formula:
    payload_hash = SHA256(canonical_json(payload))
    chain_input  = f"{sequence_number}|{previous_hash}|{payload_hash}"
    entry_hash   = SHA256(chain_input)
    """

    __tablename__ = "governance_ledger"
    __table_args__ = {"schema": "sentinel"}

    id = Column(Integer, primary_key=True, index=True)
    ledger_entry_id = Column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: f"gledger_{uuid.uuid4().hex[:12]}",
    )
    sequence_number = Column(Integer, unique=True, nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    actor_id = Column(String(64), nullable=True, index=True)
    actor_username = Column(String(64), nullable=True)
    payload = Column(JSONB, nullable=False)
    payload_hash = Column(String(64), nullable=False)
    previous_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        index=True,
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to serializable dictionary."""
        return {
            "id": self.id,
            "ledger_entry_id": self.ledger_entry_id,
            "sequence_number": self.sequence_number,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "actor_username": self.actor_username,
            "payload": self.payload,
            "payload_hash": self.payload_hash,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
