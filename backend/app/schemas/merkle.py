"""
schemas/merkle.py
-----------------
Pydantic schemas for Merkle Tree Batches, Inclusion Proofs, and Independent Verification.

Sprint 5B — Merkle Tree Proofs & Independent Auditor Verification.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import ConfigDict, BaseModel, Field


class ProofStep(BaseModel):
    """A single step in a Merkle inclusion proof path."""
    hash: str = Field(..., description="Sibling node SHA-256 hash")
    position: Literal["LEFT", "RIGHT"] = Field(
        ..., description="Position of the sibling node relative to current node"
    )


class MerkleBatchCreateRequest(BaseModel):
    """Request payload to create and seal a new Merkle batch from ledger records."""
    limit: Optional[int] = Field(
        50,
        ge=1,
        le=500,
        description="Maximum number of unbatched ledger entries to include in this Merkle batch",
    )
    ledger_batch_reference: Optional[str] = Field(
        None,
        description="Optional custom ledger batch reference identifier",
    )


class MerkleBatchResponse(BaseModel):
    """Metadata response representing a sealed Merkle batch."""
    batch_id: str
    ledger_batch_reference: str
    entry_count: int
    tree_version: str
    merkle_root: str
    root_algorithm: str
    ordering_strategy: str
    tree_status: str
    created_at: Optional[str] = None
    sealed_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class MerkleProofResponse(BaseModel):
    """Cryptographic inclusion proof response for an individual ledger entry."""
    proof_id: str
    batch_id: str
    ledger_entry_id: str
    leaf_hash: str
    proof_path: List[Dict[str, Any]]
    proof_depth: int
    tree_version: str
    merkle_root: Optional[str] = None
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class MerkleVerifyRequest(BaseModel):
    """
    Independent cryptographic verification request payload.
    Does NOT require database access or authentication.
    """
    leaf_hash: str = Field(..., description="SHA-256 hash of the target Merkle leaf")
    proof_path: List[ProofStep] = Field(
        ..., description="Ordered list of sibling nodes and positions"
    )
    merkle_root: str = Field(..., description="Expected sealed Merkle Root hash")


class MerkleVerifyResponse(BaseModel):
    """Cryptographic verification result."""
    verification_status: Literal["VALID", "INVALID"] = Field(
        ..., description="'VALID' if recomputed root matches expected, 'INVALID' otherwise"
    )
    computed_root: str = Field(..., description="Recomputed Merkle Root hash from proof")
    expected_root: str = Field(..., description="Expected sealed Merkle Root provided")
    proof_depth: int = Field(..., description="Number of hashing steps in proof path")
    reason: str = Field(..., description="Human-readable explanation of verification outcome")


class MerkleTraceEntry(BaseModel):
    """Trace details for a single ledger record in a batch."""
    ledger_entry_id: str
    sequence_number: int
    event_type: str
    ledger_entry_hash: str
    merkle_leaf_hash: str
    proof_depth: int
    verification_status: str


class MerkleTraceResponse(BaseModel):
    """Complete provenance trace linking ledger entries to Merkle tree root."""
    batch_id: str
    merkle_root: str
    tree_version: str
    tree_status: str
    entry_count: int
    tree_depth: int
    ordering_strategy: str
    entries: List[MerkleTraceEntry]
