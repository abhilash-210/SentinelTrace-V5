"""
schemas/ledger.py
-----------------
Pydantic schemas for the Cryptographic Governance Ledger.

Sprint 5A — Cryptographic Governance Ledger Foundation.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class GovernanceLedgerEntryResponse(BaseModel):
    """Schema for a single governance ledger entry."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    ledger_entry_id: str
    sequence_number: int
    event_type: str
    actor_id: Optional[str] = None
    actor_username: Optional[str] = None
    payload: Dict[str, Any]
    payload_hash: str
    previous_hash: str
    entry_hash: str
    created_at: str


class GovernanceLedgerListResponse(BaseModel):
    """Schema for paginated ledger entries."""

    total: int
    limit: int
    offset: int
    chain_head: Optional[str] = None
    items: List[GovernanceLedgerEntryResponse]


class GovernanceLedgerVerifyResponse(BaseModel):
    """Schema for cryptographic chain verification result."""

    status: str = Field(..., description="'VERIFIED' or 'TAMPER_DETECTED'")
    entries_checked: int
    chain_head: Optional[str] = None
    first_invalid_entry: Optional[str] = None
    sequence_number: Optional[int] = None
    reason: str


class GovernanceLedgerChainHeadResponse(BaseModel):
    """Schema for ledger chain head."""

    sequence_number: int
    chain_head: str
    last_event_type: str
    last_actor: Optional[str] = None
    created_at: str
