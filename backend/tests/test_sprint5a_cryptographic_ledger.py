"""
tests/test_sprint5a_cryptographic_ledger.py
-------------------------------------------
Comprehensive Automated Test Suite for Sprint 5A:
Cryptographic Governance Ledger Foundation (Deterministic SHA-256 Hash Chaining).

Test Coverage:
1. Genesis entry uses GENESIS_HASH.
2. Entry hash is valid SHA-256 format.
3. Sequential entry links to previous entry hash.
4. Valid chain verifies successfully.
5. Payload tampering is detected immediately.
6. Middle entry tampering breaks subsequent chain verification.
7. Hash generation is deterministic across multiple evaluations.
8. JSON key ordering variation does not alter payload hash.
9. Sequence numbers remain strictly continuous.
10. previous_hash modification is detected as TAMPER_DETECTED.
11. REST API /api/v1/governance-ledger returns paginated entries with chain_head.
12. REST API /api/v1/governance-ledger/verify returns cryptographic status.
13. REST API /api/v1/governance-ledger/{id} returns single entry details.
14. Policy governance operations append chained ledger entries.
"""

import hashlib
import json
import unittest
import uuid

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.ledger import GovernanceLedgerEntry
from app.services.governance_ledger_service import GENESIS_HASH, GovernanceLedgerService
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint5ACryptographicLedger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)

    def test_01_genesis_entry_uses_genesis_hash(self):
        """TEST 1: The very first ledger entry in a new chain uses GENESIS_HASH."""
        with SessionLocal() as db:
            # Clear or test on a clean isolated entry if needed
            entry = GovernanceLedgerService.append_entry(
                db=db,
                event_type="GENESIS_TEST",
                actor_id="usr_admin_001",
                actor_username="admin_demo",
                payload={"message": "Genesis block test payload"},
            )
            db.commit()

            first_entry = (
                db.query(GovernanceLedgerEntry)
                .order_by(GovernanceLedgerEntry.sequence_number.asc())
                .first()
            )
            self.assertIsNotNone(first_entry)
            self.assertEqual(first_entry.sequence_number, 1)
            self.assertEqual(first_entry.previous_hash, GENESIS_HASH)

    def test_02_entry_hash_is_valid_sha256(self):
        """TEST 2: Entry hash and payload hash are valid 64-char hexadecimal SHA-256 strings."""
        with SessionLocal() as db:
            entry = GovernanceLedgerService.append_entry(
                db=db,
                event_type="POLICY_CREATED",
                actor_id="usr_author_002",
                actor_username="author_demo",
                payload={"policy_id": "spol_test_01", "name": "Test Policy"},
            )
            db.commit()

            self.assertEqual(len(entry.payload_hash), 64)
            self.assertEqual(len(entry.entry_hash), 64)
            int(entry.payload_hash, 16)  # Asserts valid hex
            int(entry.entry_hash, 16)

    def test_03_subsequent_entry_links_to_previous_hash(self):
        """TEST 3: Each subsequent entry links strictly to the entry_hash of the preceding sequence."""
        with SessionLocal() as db:
            entry_a = GovernanceLedgerService.append_entry(
                db=db,
                event_type="POLICY_SUBMITTED",
                actor_id="usr_author_002",
                actor_username="author_demo",
                payload={"policy_id": "spol_test_02", "step": "A"},
            )
            db.commit()

            entry_b = GovernanceLedgerService.append_entry(
                db=db,
                event_type="POLICY_APPROVED",
                actor_id="usr_reviewer_003",
                actor_username="reviewer_demo",
                payload={"policy_id": "spol_test_02", "step": "B"},
            )
            db.commit()

            self.assertEqual(entry_b.sequence_number, entry_a.sequence_number + 1)
            self.assertEqual(entry_b.previous_hash, entry_a.entry_hash)

    def test_04_valid_chain_verifies_successfully(self):
        """TEST 4: Entire valid ledger chain passes cryptographic verification."""
        with SessionLocal() as db:
            result = GovernanceLedgerService.verify_chain(db)
            self.assertEqual(result["status"], "VERIFIED")
            self.assertGreaterEqual(result["entries_checked"], 1)
            self.assertIsNone(result["first_invalid_entry"])
            self.assertIsNotNone(result["chain_head"])

    def test_05_payload_tampering_detected(self):
        """TEST 5: Modifying the payload of any entry triggers TAMPER_DETECTED."""
        with SessionLocal() as db:
            # Create entry to tamper
            entry = GovernanceLedgerService.append_entry(
                db=db,
                event_type="TAMPER_TEST",
                actor_id="usr_admin_001",
                actor_username="admin_demo",
                payload={"secret_key": "original_value"},
            )
            db.commit()

            original_payload = dict(entry.payload)
            # Mutate payload in DB directly
            entry.payload = {"secret_key": "TAMPERED_VALUE"}
            db.commit()

            # Verify chain
            verif = GovernanceLedgerService.verify_chain(db)
            self.assertEqual(verif["status"], "TAMPER_DETECTED")
            self.assertEqual(verif["first_invalid_entry"], entry.ledger_entry_id)
            self.assertIn("Payload hash mismatch", verif["reason"])

            # Restore payload
            entry.payload = original_payload
            db.commit()

            # Verify chain restored
            verif_restored = GovernanceLedgerService.verify_chain(db)
            self.assertEqual(verif_restored["status"], "VERIFIED")

    def test_06_middle_entry_hash_tampering_breaks_verification(self):
        """TEST 6: Modifying entry_hash of an entry breaks subsequent linkage and entry hash verification."""
        with SessionLocal() as db:
            entry = GovernanceLedgerService.append_entry(
                db=db,
                event_type="HASH_TAMPER_TEST",
                actor_id="usr_admin_001",
                actor_username="admin_demo",
                payload={"action": "test"},
            )
            db.commit()

            orig_entry_hash = entry.entry_hash
            entry.entry_hash = "deadbeef" * 8
            db.commit()

            verif = GovernanceLedgerService.verify_chain(db)
            self.assertEqual(verif["status"], "TAMPER_DETECTED")
            self.assertEqual(verif["first_invalid_entry"], entry.ledger_entry_id)

            # Restore
            entry.entry_hash = orig_entry_hash
            db.commit()

    def test_07_hash_generation_is_deterministic(self):
        """TEST 7: Hash computation produces identical results across multiple calls."""
        payload = {"b": 2, "a": 1, "nested": {"z": 100, "y": 200}}
        hash1 = GovernanceLedgerService.calculate_payload_hash(payload)
        hash2 = GovernanceLedgerService.calculate_payload_hash(payload)
        self.assertEqual(hash1, hash2)

        entry_hash1 = GovernanceLedgerService.calculate_entry_hash(5, "prev_hash_123", hash1)
        entry_hash2 = GovernanceLedgerService.calculate_entry_hash(5, "prev_hash_123", hash1)
        self.assertEqual(entry_hash1, entry_hash2)

    def test_08_json_key_ordering_does_not_change_hash(self):
        """TEST 8: Canonical JSON serialization guarantees dictionary key order independence."""
        payload1 = {"alpha": 1, "beta": 2, "gamma": 3}
        payload2 = {"gamma": 3, "alpha": 1, "beta": 2}
        payload3 = {"beta": 2, "gamma": 3, "alpha": 1}

        hash1 = GovernanceLedgerService.calculate_payload_hash(payload1)
        hash2 = GovernanceLedgerService.calculate_payload_hash(payload2)
        hash3 = GovernanceLedgerService.calculate_payload_hash(payload3)

        self.assertEqual(hash1, hash2)
        self.assertEqual(hash2, hash3)

    def test_09_sequence_numbers_remain_strictly_continuous(self):
        """TEST 9: Sequence numbers are sequential integers without gaps."""
        with SessionLocal() as db:
            entries = (
                db.query(GovernanceLedgerEntry)
                .order_by(GovernanceLedgerEntry.sequence_number.asc())
                .all()
            )
            for idx, entry in enumerate(entries):
                self.assertEqual(entry.sequence_number, idx + 1)

    def test_10_previous_hash_modification_detected(self):
        """TEST 10: Modifying previous_hash in a block triggers TAMPER_DETECTED."""
        with SessionLocal() as db:
            entry = GovernanceLedgerService.append_entry(
                db=db,
                event_type="PREV_HASH_TEST",
                actor_id="usr_admin_001",
                actor_username="admin_demo",
                payload={"action": "test_prev_hash"},
            )
            db.commit()

            orig_prev_hash = entry.previous_hash
            entry.previous_hash = "cafebabe" * 8
            db.commit()

            verif = GovernanceLedgerService.verify_chain(db)
            self.assertEqual(verif["status"], "TAMPER_DETECTED")
            self.assertEqual(verif["first_invalid_entry"], entry.ledger_entry_id)

            # Restore
            entry.previous_hash = orig_prev_hash
            db.commit()

    def test_11_api_get_ledger_entries(self):
        """TEST 11: GET /api/v1/governance-ledger returns paginated entries with chain_head."""
        auditor_headers = get_auth_headers("AUDITOR")
        res = client.get("/api/v1/governance-ledger", headers=auditor_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total", data)
        self.assertIn("items", data)
        self.assertIn("chain_head", data)
        self.assertGreaterEqual(len(data["items"]), 1)

    def test_12_api_verify_ledger_chain(self):
        """TEST 12: GET /api/v1/governance-ledger/verify returns cryptographic status."""
        auditor_headers = get_auth_headers("AUDITOR")
        res = client.get("/api/v1/governance-ledger/verify", headers=auditor_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "VERIFIED")
        self.assertGreaterEqual(data["entries_checked"], 1)

    def test_13_api_get_single_entry_detail(self):
        """TEST 13: GET /api/v1/governance-ledger/{id} returns single entry inspection."""
        with SessionLocal() as db:
            latest = (
                db.query(GovernanceLedgerEntry)
                .order_by(GovernanceLedgerEntry.sequence_number.desc())
                .first()
            )
            self.assertIsNotNone(latest)
            target_id = latest.ledger_entry_id

        auditor_headers = get_auth_headers("AUDITOR")
        res = client.get(f"/api/v1/governance-ledger/{target_id}", headers=auditor_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["ledger_entry_id"], target_id)
        self.assertIn("payload", data)
        self.assertIn("payload_hash", data)
        self.assertIn("entry_hash", data)
        self.assertIn("previous_hash", data)

    def test_14_policy_governance_actions_create_ledger_entries(self):
        """TEST 14: Submitting and approving a policy automatically generates chained ledger entries."""
        author_headers = get_auth_headers("POLICY_AUTHOR")
        reviewer_headers = get_auth_headers("POLICY_REVIEWER")

        # 1. Create Draft Policy
        p_payload = {
            "policy_name": f"Ledger Trace Policy {uuid.uuid4().hex[:6]}",
            "vendor_name": f"Vendor_{uuid.uuid4().hex[:6]}",
            "source_profile_id": "sp_firewall_syslog",
            "status": "DRAFT",
            "rules": [],
        }
        create_res = client.post("/api/v1/semantic-policies", json=p_payload, headers=author_headers)
        self.assertEqual(create_res.status_code, 201)
        policy_id = create_res.json()["policy_id"]

        # 2. Submit policy for review
        sub_res = client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)
        self.assertEqual(sub_res.status_code, 200)
        app_id = sub_res.json()["approval_id"]

        # 3. Reviewer approves
        app_res = client.post(f"/api/v1/policy-approvals/{app_id}/approve", json={"review_comment": "Ledger verified"}, headers=reviewer_headers)
        self.assertEqual(app_res.status_code, 200)

        # 4. Check that ledger entries were created for these actions
        with SessionLocal() as db:
            sub_entry = (
                db.query(GovernanceLedgerEntry)
                .filter(GovernanceLedgerEntry.event_type == "POLICY_SUBMITTED")
                .order_by(GovernanceLedgerEntry.sequence_number.desc())
                .first()
            )
            self.assertIsNotNone(sub_entry)

            app_entry = (
                db.query(GovernanceLedgerEntry)
                .filter(GovernanceLedgerEntry.event_type == "POLICY_APPROVED")
                .order_by(GovernanceLedgerEntry.sequence_number.desc())
                .first()
            )
            self.assertIsNotNone(app_entry)

            # Chain verification still passes
            verif = GovernanceLedgerService.verify_chain(db)
            self.assertEqual(verif["status"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
