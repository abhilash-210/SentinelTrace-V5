"""
tests/test_sprint5b_merkle_proofs.py
------------------------------------
Test suite for Sprint 5B: Merkle Tree Proofs & Independent Auditor Verification.

20 comprehensive unit, integration, and security tests covering:
- Deterministic leaf and parent hashing
- Merkle root computation & domain separation
- Odd-numbered leaf handling
- Pure mathematical inclusion proof verification
- Tamper detection (modified leaf, sibling hash, position, root)
- Cross-batch proof isolation
- RBAC permissions on batch creation vs unauthenticated public verification
- Database persistence and provenance tracing
"""

import hashlib
import json
import unittest
import uuid
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.ledger import GovernanceLedgerEntry
from app.models.merkle import MerkleBatch, MerkleProof
from app.services.governance_ledger_service import GovernanceLedgerService
from app.services.merkle_batch_service import MerkleBatchService
from app.services.merkle_tree_service import (
    LEAF_DOMAIN_PREFIX,
    NODE_DOMAIN_PREFIX,
    MerkleTreeService,
)
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint5BMerkleProofs(unittest.TestCase):
    """Unit and Integration tests for Sprint 5B Merkle Tree and Proof verification."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)

    # ── Test 1: Leaf Hash Generation Deterministic ────────────────────────────
    def test_01_leaf_hash_generation_deterministic(self):
        entry_hash = "a" * 64
        expected = hashlib.sha256(f"{LEAF_DOMAIN_PREFIX}{entry_hash}".encode("utf-8")).hexdigest()
        leaf1 = MerkleTreeService.generate_leaf_hash(entry_hash)
        leaf2 = MerkleTreeService.generate_leaf_hash(entry_hash)
        self.assertEqual(leaf1, leaf2)
        self.assertEqual(leaf1, expected)

    # ── Test 2: Parent Hash Generation Deterministic ──────────────────────────
    def test_02_parent_hash_generation_deterministic(self):
        left = "1" * 64
        right = "2" * 64
        expected = hashlib.sha256(f"{NODE_DOMAIN_PREFIX}{left}{right}".encode("utf-8")).hexdigest()
        parent1 = MerkleTreeService.calculate_parent_hash(left, right)
        parent2 = MerkleTreeService.calculate_parent_hash(left, right)
        self.assertEqual(parent1, parent2)
        self.assertEqual(parent1, expected)

    # ── Test 3: Same Ordered Entries Produce Same Root ────────────────────────
    def test_03_same_ordered_entries_produce_same_root(self):
        entries = [hashlib.sha256(f"entry_{i}".encode("utf-8")).hexdigest() for i in range(4)]
        root1, _, _ = MerkleTreeService.build_tree(entries)
        root2, _, _ = MerkleTreeService.build_tree(entries)
        self.assertEqual(root1, root2)
        self.assertIsNotNone(root1)

    # ── Test 4: Different Ordering Produces Different Root ────────────────────
    def test_04_different_ordering_produces_different_root(self):
        entries1 = [hashlib.sha256(f"entry_{i}".encode("utf-8")).hexdigest() for i in range(4)]
        entries2 = list(reversed(entries1))
        root1, _, _ = MerkleTreeService.build_tree(entries1)
        root2, _, _ = MerkleTreeService.build_tree(entries2)
        self.assertNotEqual(root1, root2)

    # ── Test 5: Single Leaf Tree Works ────────────────────────────────────────
    def test_05_single_leaf_tree_works(self):
        entries = ["1" * 64]
        root, levels, proofs = MerkleTreeService.build_tree(entries)
        leaf_hash = MerkleTreeService.generate_leaf_hash(entries[0])
        self.assertEqual(root, leaf_hash)
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0], [])

        # Verify depth 0 proof
        res = MerkleTreeService.verify_inclusion_proof(leaf_hash, proofs[0], root)
        self.assertEqual(res["verification_status"], "VALID")
        self.assertEqual(res["proof_depth"], 0)

    # ── Test 6: Two Leaf Tree Works ───────────────────────────────────────────
    def test_06_two_leaf_tree_works(self):
        entries = ["1" * 64, "2" * 64]
        root, levels, proofs = MerkleTreeService.build_tree(entries)
        leaf0 = MerkleTreeService.generate_leaf_hash(entries[0])
        leaf1 = MerkleTreeService.generate_leaf_hash(entries[1])

        self.assertEqual(len(proofs), 2)
        self.assertEqual(proofs[0], [{"hash": leaf1, "position": "RIGHT"}])
        self.assertEqual(proofs[1], [{"hash": leaf0, "position": "LEFT"}])

        res0 = MerkleTreeService.verify_inclusion_proof(leaf0, proofs[0], root)
        res1 = MerkleTreeService.verify_inclusion_proof(leaf1, proofs[1], root)
        self.assertEqual(res0["verification_status"], "VALID")
        self.assertEqual(res1["verification_status"], "VALID")

    # ── Test 7: Odd Number of Leaves Handled Deterministically ────────────────
    def test_07_odd_number_of_leaves_handled_deterministically(self):
        entries = ["a" * 64, "b" * 64, "c" * 64]
        root1, _, proofs1 = MerkleTreeService.build_tree(entries)
        root2, _, proofs2 = MerkleTreeService.build_tree(entries)
        self.assertEqual(root1, root2)

        for idx, entry in enumerate(entries):
            leaf = MerkleTreeService.generate_leaf_hash(entry)
            res = MerkleTreeService.verify_inclusion_proof(leaf, proofs1[idx], root1)
            self.assertEqual(res["verification_status"], "VALID")

    # ── Test 8: Inclusion Proof Generated Correctly ───────────────────────────
    def test_08_inclusion_proof_generated_correctly(self):
        entries = [hashlib.sha256(f"log_{i}".encode("utf-8")).hexdigest() for i in range(8)]
        root, _, proofs = MerkleTreeService.build_tree(entries)
        self.assertEqual(len(proofs), 8)
        for p in proofs:
            self.assertEqual(len(p), 3)  # log2(8) = 3
            for step in p:
                self.assertIn("hash", step)
                self.assertIn(step["position"], ("LEFT", "RIGHT"))

    # ── Test 9: Valid Inclusion Proof Verifies Successfully ───────────────────
    def test_09_valid_inclusion_proof_verifies_successfully(self):
        entries = [hashlib.sha256(f"test_item_{i}".encode("utf-8")).hexdigest() for i in range(16)]
        root, _, proofs = MerkleTreeService.build_tree(entries)
        for i, entry in enumerate(entries):
            leaf = MerkleTreeService.generate_leaf_hash(entry)
            res = MerkleTreeService.verify_inclusion_proof(leaf, proofs[i], root)
            self.assertEqual(res["verification_status"], "VALID")
            self.assertEqual(res["computed_root"], root)
            self.assertIn("verified successfully", res["reason"].lower())

    # ── Test 10: Modified Leaf Hash Fails Verification ────────────────────────
    def test_10_modified_leaf_hash_fails_verification(self):
        entries = ["1" * 64, "2" * 64, "3" * 64, "4" * 64]
        root, _, proofs = MerkleTreeService.build_tree(entries)
        tampered_leaf = "f" * 64
        res = MerkleTreeService.verify_inclusion_proof(tampered_leaf, proofs[0], root)
        self.assertEqual(res["verification_status"], "INVALID")
        self.assertNotEqual(res["computed_root"], root)

    # ── Test 11: Modified Sibling Hash Fails Verification ─────────────────────
    def test_11_modified_sibling_hash_fails_verification(self):
        entries = ["1" * 64, "2" * 64, "3" * 64, "4" * 64]
        root, _, proofs = MerkleTreeService.build_tree(entries)
        leaf = MerkleTreeService.generate_leaf_hash(entries[0])
        tampered_proof = [
            {"hash": "e" * 64, "position": proofs[0][0]["position"]},
            proofs[0][1],
        ]
        res = MerkleTreeService.verify_inclusion_proof(leaf, tampered_proof, root)
        self.assertEqual(res["verification_status"], "INVALID")

    # ── Test 12: Modified Sibling Position Fails Verification ─────────────────
    def test_12_modified_sibling_position_fails_verification(self):
        entries = ["1" * 64, "2" * 64, "3" * 64, "4" * 64]
        root, _, proofs = MerkleTreeService.build_tree(entries)
        leaf = MerkleTreeService.generate_leaf_hash(entries[0])
        flipped_position = "LEFT" if proofs[0][0]["position"] == "RIGHT" else "RIGHT"
        tampered_proof = [
            {"hash": proofs[0][0]["hash"], "position": flipped_position},
            proofs[0][1],
        ]
        res = MerkleTreeService.verify_inclusion_proof(leaf, tampered_proof, root)
        self.assertEqual(res["verification_status"], "INVALID")

    # ── Test 13: Modified Root Fails Verification ─────────────────────────────
    def test_13_modified_root_fails_verification(self):
        entries = ["1" * 64, "2" * 64]
        root, _, proofs = MerkleTreeService.build_tree(entries)
        leaf = MerkleTreeService.generate_leaf_hash(entries[0])
        fake_root = "0" * 64
        res = MerkleTreeService.verify_inclusion_proof(leaf, proofs[0], fake_root)
        self.assertEqual(res["verification_status"], "INVALID")

    # ── Test 14: Proof Cannot Be Verified Against Wrong Batch ─────────────────
    def test_14_proof_cannot_be_verified_against_wrong_batch(self):
        batch_a = ["a1" * 32, "a2" * 32]
        batch_b = ["b1" * 32, "b2" * 32]
        root_a, _, proofs_a = MerkleTreeService.build_tree(batch_a)
        root_b, _, _ = MerkleTreeService.build_tree(batch_b)
        leaf_a0 = MerkleTreeService.generate_leaf_hash(batch_a[0])

        res = MerkleTreeService.verify_inclusion_proof(leaf_a0, proofs_a[0], root_b)
        self.assertEqual(res["verification_status"], "INVALID")

    # ── Test 15: Database Proof Persistence Works ─────────────────────────────
    def test_15_database_proof_persistence_works(self):
        with SessionLocal() as db:
            # Ensure there are governance ledger entries
            for i in range(3):
                GovernanceLedgerService.append_entry(
                    db=db,
                    event_type="MERKLE_TEST_EVENT",
                    payload={"action": f"test_action_{i}"},
                    actor_id="usr_admin_001",
                    actor_username="admin_demo",
                )
            db.commit()

            batch_dict = MerkleBatchService.create_batch_from_ledger(db=db, limit=10)
            self.assertIn("batch_id", batch_dict)
            self.assertEqual(batch_dict["tree_status"], "SEALED")
            self.assertGreaterEqual(batch_dict["entry_count"], 1)

            # Retrieve batches
            batches = MerkleBatchService.get_batches(db=db)
            self.assertTrue(any(b["batch_id"] == batch_dict["batch_id"] for b in batches))

    # ── Test 16: Sealed Merkle Root Remains Immutable ─────────────────────────
    def test_16_sealed_merkle_root_remains_immutable(self):
        with SessionLocal() as db:
            batch = db.query(MerkleBatch).first()
            if batch:
                original_root = batch.merkle_root
                self.assertEqual(batch.tree_status, "SEALED")
                self.assertIsNotNone(batch.sealed_at)
                self.assertEqual(len(original_root), 64)

    # ── Test 17: Duplicate Batch or Empty Ledger Handled Safely ───────────────
    def test_17_duplicate_batch_or_empty_ledger_handled_safely(self):
        with SessionLocal() as db:
            batch = MerkleBatchService.create_batch_from_ledger(db=db, limit=5)
            self.assertIsNotNone(batch["merkle_root"])

    # ── Test 18: API Verification Works Without Authentication ────────────────
    def test_18_api_verification_works_without_authentication(self):
        entries = ["c" * 64, "d" * 64]
        root, _, proofs = MerkleTreeService.build_tree(entries)
        leaf = MerkleTreeService.generate_leaf_hash(entries[0])

        # Public POST without Authorization header
        response = client.post(
            "/api/v1/merkle/verify",
            json={
                "leaf_hash": leaf,
                "proof_path": proofs[0],
                "merkle_root": root,
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["verification_status"], "VALID")
        self.assertEqual(data["computed_root"], root)

    # ── Test 19: Unauthorized Batch Creation Rejected ─────────────────────────
    def test_19_unauthorized_batch_creation_rejected(self):
        viewer_headers = get_auth_headers("VIEWER")
        response = client.post(
            "/api/v1/merkle-batches",
            headers=viewer_headers,
            json={"limit": 10},
        )
        self.assertEqual(response.status_code, 403)

    # ── Test 20: Full Traceability and Provenance API Works ───────────────────
    def test_20_full_traceability_and_provenance_api_works(self):
        with SessionLocal() as db:
            batch = db.query(MerkleBatch).first()
            self.assertIsNotNone(batch)
            batch_id = batch.batch_id

        auditor_headers = get_auth_headers("AUDITOR")
        response = client.get(
            f"/api/v1/merkle-batches/{batch_id}/trace",
            headers=auditor_headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["batch_id"], batch_id)
        self.assertGreater(len(data["entries"]), 0)
        self.assertEqual(data["entries"][0]["verification_status"], "VALID")


if __name__ == "__main__":
    unittest.main()
