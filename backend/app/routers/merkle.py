"""
routers/merkle.py
-----------------
FastAPI router for Merkle Tree Batches, Inclusion Proofs, and Independent Auditor Verification.

Sprint 5B — Merkle Tree Proofs & Independent Auditor Verification.

Endpoints:
- POST /api/v1/merkle-batches: Create sealed Merkle batch (Auth + MERKLE_BATCH_CREATE)
- GET  /api/v1/merkle-batches: List Merkle batches (Auth + MERKLE_BATCH_READ)
- GET  /api/v1/merkle-batches/{batch_id}: Get batch details (Auth + MERKLE_BATCH_READ)
- GET  /api/v1/merkle-batches/{batch_id}/trace: Complete provenance trace (Auth + MERKLE_BATCH_READ)
- GET  /api/v1/merkle-proofs/{ledger_entry_id}: Retrieve inclusion proof (Auth + MERKLE_PROOF_READ)
- POST /api/v1/merkle/verify: Independent zero-database mathematical verification (PUBLIC, NO AUTH REQUIRED)
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.schemas.merkle import (
    MerkleBatchCreateRequest,
    MerkleBatchResponse,
    MerkleProofResponse,
    MerkleTraceResponse,
    MerkleVerifyRequest,
    MerkleVerifyResponse,
)
from app.services.merkle_batch_service import MerkleBatchService
from app.services.merkle_tree_service import MerkleTreeService

logger = logging.getLogger("sentinel.routers.merkle")

router = APIRouter(prefix="/api/v1", tags=["Merkle Tree Audit & Proofs"])


@router.post(
    "/merkle-batches",
    response_model=MerkleBatchResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create and seal a new Merkle batch from governance ledger records",
)
def create_merkle_batch(
    payload: MerkleBatchCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MERKLE_BATCH_CREATE)),
):
    """
    Creates and seals a deterministic Merkle batch over immutable governance ledger entries.
    Requires ADMIN or users with MERKLE_BATCH_CREATE permission.
    """
    try:
        batch = MerkleBatchService.create_batch_from_ledger(
            db=db,
            limit=payload.limit or 50,
            custom_batch_ref=payload.ledger_batch_reference,
        )
        return batch
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except Exception as exc:
        logger.error(f"Error creating Merkle batch: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to seal Merkle batch: {str(exc)}",
        )


@router.get(
    "/merkle-batches",
    response_model=List[MerkleBatchResponse],
    summary="List all sealed Merkle batches",
)
def list_merkle_batches(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MERKLE_BATCH_READ)),
):
    """Returns a list of all sealed Merkle batches ordered by newest first."""
    return MerkleBatchService.get_batches(db=db, limit=limit, offset=offset)


@router.get(
    "/merkle-batches/{batch_id}",
    response_model=MerkleBatchResponse,
    summary="Get Merkle batch metadata by batch_id",
)
def get_merkle_batch(
    batch_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MERKLE_BATCH_READ)),
):
    """Retrieve metadata for a specific sealed Merkle batch."""
    batch = MerkleBatchService.get_batch_by_id(db=db, batch_id=batch_id)
    if not batch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Merkle batch '{batch_id}' not found.",
        )
    return batch


@router.get(
    "/merkle-batches/{batch_id}/trace",
    response_model=MerkleTraceResponse,
    summary="Get complete cryptographic provenance trace for a batch",
)
def get_merkle_batch_trace(
    batch_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MERKLE_BATCH_READ)),
):
    """
    Returns complete cryptographic trace from ledger entries through inclusion proofs to Merkle root.
    """
    trace = MerkleBatchService.get_batch_trace(db=db, batch_id=batch_id)
    if not trace:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Merkle batch '{batch_id}' not found for provenance tracing.",
        )
    return trace


@router.get(
    "/merkle-proofs/{ledger_entry_id}",
    response_model=MerkleProofResponse,
    summary="Get inclusion proof for a ledger entry",
)
def get_merkle_proof(
    ledger_entry_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MERKLE_PROOF_READ)),
):
    """
    Retrieves the Merkle inclusion proof for a specific governance ledger entry.
    """
    proof = MerkleBatchService.get_proof_by_ledger_entry_id(
        db=db, ledger_entry_id=ledger_entry_id
    )
    if not proof:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No inclusion proof found for ledger entry '{ledger_entry_id}'.",
        )
    return proof


@router.post(
    "/merkle/verify",
    response_model=MerkleVerifyResponse,
    summary="Independent zero-trust cryptographic Merkle proof verification",
)
def verify_merkle_proof(
    payload: MerkleVerifyRequest,
):
    """
    PURE MATHEMATICAL CRYPTOGRAPHIC VERIFICATION.

    This endpoint performs independent Merkle inclusion proof verification.
    It does NOT require authentication, database connection, or trust in SentinelTrace backend state.
    'Trust the mathematics, not the database.'
    """
    steps = [s.model_dump() if hasattr(s, "model_dump") else s.dict() for s in payload.proof_path]
    result = MerkleTreeService.verify_inclusion_proof(
        leaf_hash=payload.leaf_hash,
        proof_path=steps,
        merkle_root=payload.merkle_root,
    )
    return result
