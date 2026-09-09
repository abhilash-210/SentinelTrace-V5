"""
services/merkle_tree_service.py
-------------------------------
Deterministic Merkle Tree construction and Pure Cryptographic Inclusion Proof Verification.

Sprint 5B — Merkle Tree Proofs & Independent Auditor Verification.

Mathematical Properties:
1. Domain Separation Prefixes:
   - Leaf:   SHA256("SENTINELTRACE_MERKLE_LEAF_V1" || entry_hash)
   - Node:   SHA256("SENTINELTRACE_MERKLE_NODE_V1" || left_child_hash || right_child_hash)
   - Root:   Final tree apex hash
2. Odd Leaf Strategy:
   - Duplicate final leaf at any odd-sized level: [A, B, C] -> [A, B, C, C]
3. Independent Verification:
   - Pure mathematical validation requiring NO database, NO ORM, and NO backend state.
"""

import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.services.merkle")

LEAF_DOMAIN_PREFIX = "SENTINELTRACE_MERKLE_LEAF_V1"
NODE_DOMAIN_PREFIX = "SENTINELTRACE_MERKLE_NODE_V1"
ROOT_DOMAIN_PREFIX = "SENTINELTRACE_MERKLE_ROOT_V1"


class MerkleTreeService:
    """Pure cryptographic service for deterministic Merkle Tree generation and verification."""

    @staticmethod
    def generate_leaf_hash(entry_hash: str) -> str:
        """
        Generate deterministic leaf hash with domain separation prefix.
        Formula: SHA256(LEAF_DOMAIN_PREFIX || entry_hash)
        """
        raw = f"{LEAF_DOMAIN_PREFIX}{entry_hash}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def calculate_parent_hash(left_hash: str, right_hash: str) -> str:
        """
        Generate deterministic parent node hash from left and right child hashes.
        Formula: SHA256(NODE_DOMAIN_PREFIX || left_hash || right_hash)
        """
        raw = f"{NODE_DOMAIN_PREFIX}{left_hash}{right_hash}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def build_tree(
        cls, entry_hashes: List[str]
    ) -> Tuple[Optional[str], List[List[str]], List[List[Dict[str, str]]]]:
        """
        Construct a deterministic Merkle Tree from an ordered list of ledger entry hashes.

        Returns:
            - merkle_root: SHA-256 root hash of the tree
            - tree_levels: List of levels from leaves (index 0) to root
            - proofs: Inclusion proof path for each corresponding input entry
        """
        if not entry_hashes:
            return None, [], []

        # 1. Generate leaves
        leaves = [cls.generate_leaf_hash(h) for h in entry_hashes]
        n_entries = len(leaves)

        if n_entries == 1:
            root = leaves[0]
            return root, [leaves], [[]]

        # Initialize proof tracking for each entry index
        proofs: List[List[Dict[str, str]]] = [[] for _ in range(n_entries)]
        current_indices = list(range(n_entries))

        tree_levels: List[List[str]] = [leaves.copy()]
        current_level = leaves.copy()

        while len(current_level) > 1:
            # Handle odd number of elements by duplicating the last node
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])

            # Record sibling for each active entry index
            for entry_idx, node_idx in enumerate(current_indices):
                if node_idx % 2 == 0:
                    sibling_idx = node_idx + 1
                    position = "RIGHT"
                else:
                    sibling_idx = node_idx - 1
                    position = "LEFT"

                proofs[entry_idx].append(
                    {
                        "hash": current_level[sibling_idx],
                        "position": position,
                    }
                )
                # Map to parent index in next level
                current_indices[entry_idx] = node_idx // 2

            # Compute next level parent hashes
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                parent = cls.calculate_parent_hash(
                    current_level[i], current_level[i + 1]
                )
                next_level.append(parent)

            tree_levels.append(next_level.copy())
            current_level = next_level

        merkle_root = current_level[0]
        return merkle_root, tree_levels, proofs

    @classmethod
    def verify_inclusion_proof(
        cls,
        leaf_hash: str,
        proof_path: List[Dict[str, Any]],
        merkle_root: str,
    ) -> Dict[str, Any]:
        """
        Pure, zero-database cryptographic verification of a Merkle inclusion proof.

        Algorithm:
        1. Start with current_hash = leaf_hash
        2. For each step in proof_path:
           - If sibling position == 'LEFT': parent = SHA256(NODE_PREFIX || sibling_hash || current_hash)
           - If sibling position == 'RIGHT': parent = SHA256(NODE_PREFIX || current_hash || sibling_hash)
           - current_hash = parent
        3. Compare current_hash with expected merkle_root.

        Returns:
            Dict containing verification_status ('VALID' | 'INVALID'), computed_root, expected_root, proof_depth, and reason.
        """
        if not leaf_hash:
            return {
                "verification_status": "INVALID",
                "computed_root": "",
                "expected_root": merkle_root or "",
                "proof_depth": 0,
                "reason": "Missing or empty leaf hash provided for verification.",
            }

        if not merkle_root:
            return {
                "verification_status": "INVALID",
                "computed_root": "",
                "expected_root": "",
                "proof_depth": len(proof_path or []),
                "reason": "Missing or empty expected Merkle root provided for verification.",
            }

        current_hash = leaf_hash.strip().lower()
        expected_root = merkle_root.strip().lower()
        steps = proof_path or []

        for idx, step in enumerate(steps):
            sibling_hash = step.get("hash", "").strip().lower()
            position = step.get("position", "").strip().upper()

            if not sibling_hash or position not in ("LEFT", "RIGHT"):
                return {
                    "verification_status": "INVALID",
                    "computed_root": current_hash,
                    "expected_root": expected_root,
                    "proof_depth": len(steps),
                    "reason": f"Malformed proof step at index {idx}: missing hash or invalid position '{position}'.",
                }

            if position == "LEFT":
                current_hash = cls.calculate_parent_hash(sibling_hash, current_hash)
            elif position == "RIGHT":
                current_hash = cls.calculate_parent_hash(current_hash, sibling_hash)

        if current_hash == expected_root:
            return {
                "verification_status": "VALID",
                "computed_root": current_hash,
                "expected_root": expected_root,
                "proof_depth": len(steps),
                "reason": "Cryptographic inclusion proof verified successfully. Mathematical recomputation matches sealed Merkle root.",
            }
        else:
            return {
                "verification_status": "INVALID",
                "computed_root": current_hash,
                "expected_root": expected_root,
                "proof_depth": len(steps),
                "reason": "Computed Merkle root does not match expected sealed root. Cryptographic mismatch detected.",
            }
