"""
routers/governance_ledger.py
----------------------------
REST API Router for the Cryptographic Governance Ledger.

Sprint 5A — Cryptographic Governance Ledger Foundation.
Provides:
- GET /api/v1/governance-ledger (Paginated list)
- GET /api/v1/governance-ledger/verify (Full cryptographic chain verification)
- GET /api/v1/governance-ledger/{ledger_entry_id} (Single entry detail inspection)
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.core.auth import get_current_user, require_any_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.schemas.ledger import (
    GovernanceLedgerEntryResponse,
    GovernanceLedgerListResponse,
    GovernanceLedgerVerifyResponse,
)
from app.services.governance_ledger_service import GovernanceLedgerService

logger = logging.getLogger("sentinel.routers.ledger")

router = APIRouter(
    prefix="/api/v1/governance-ledger",
    tags=["Cryptographic Governance Ledger"],
)


@router.get(
    "/verify",
    response_model=GovernanceLedgerVerifyResponse,
    summary="Cryptographic Chain Verification",
    description=(
        "Traverses and cryptographically validates the entire governance ledger from Genesis to Head. "
        "Verifies sequential numbering, previous_hash linkage, canonical payload SHA-256 hashes, "
        "and entry SHA-256 hashes."
    ),
)
def verify_governance_ledger_chain(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_any_permission([Permission.AUDIT_READ, Permission.GOVERNANCE_AUDIT_READ])
    ),
):
    """Full cryptographic ledger verification."""
    result = GovernanceLedgerService.verify_chain(db)
    return result


@router.get(
    "",
    response_model=GovernanceLedgerListResponse,
    summary="List Governance Ledger Entries",
    description="Retrieves a paginated list of append-only, cryptographically chained governance ledger entries.",
)
def list_governance_ledger_entries(
    limit: int = Query(50, ge=1, le=500, description="Max entries to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    actor_id: Optional[str] = Query(None, description="Filter by actor ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_any_permission([Permission.AUDIT_READ, Permission.GOVERNANCE_AUDIT_READ])
    ),
):
    """List paginated ledger entries."""
    items, total = GovernanceLedgerService.get_entries(
        db=db,
        limit=limit,
        offset=offset,
        event_type=event_type,
        actor_id=actor_id,
    )
    chain_head_entry = GovernanceLedgerService.get_chain_head(db)
    chain_head_hash = chain_head_entry["entry_hash"] if chain_head_entry else GovernanceLedgerService.GENESIS_HASH

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "chain_head": chain_head_hash,
        "items": items,
    }


@router.get(
    "/{ledger_entry_id}",
    response_model=GovernanceLedgerEntryResponse,
    summary="Get Governance Ledger Entry Detail",
    description="Retrieves a single cryptographic ledger entry by unique entry ID.",
)
def get_governance_ledger_entry(
    ledger_entry_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_any_permission([Permission.AUDIT_READ, Permission.GOVERNANCE_AUDIT_READ])
    ),
):
    """Get single ledger entry detail."""
    entry = GovernanceLedgerService.get_entry_by_id(db, ledger_entry_id)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Governance ledger entry '{ledger_entry_id}' not found.",
        )
    return entry
