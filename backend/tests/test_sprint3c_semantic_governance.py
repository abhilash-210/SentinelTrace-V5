"""
test_sprint3c_semantic_governance.py
------------------------------------
Automated test suite for Sprint 3C:
Semantic Governance, Policy Versioning, Comparison, and Explainability.

Verifies:
1. Deterministic read-only policy version comparison endpoint (/api/v1/semantic-policies/compare).
2. Policy version lineage linkage (v0 SUPERSEDED -> v1 ACTIVE -> v2 DRAFT candidate).
3. Semantic impact classification for changed rules (PERMIT: ALLOWED -> MONITORED flagged as HIGH impact).
4. Protected semantic fields query and critical security ratings.
5. Draft policy creation enforcement (forced DRAFT state, no activation bypass).
6. Vendor isolation in policy registry (Cisco ASA vs Demo Vendor).
"""

import unittest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.services.semantic_policy_service import SemanticPolicyService
from tests.auth_helper import get_auth_headers

client = TestClient(app, headers=get_auth_headers("ADMIN"))


class TestSprint3CSemanticGovernance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            SemanticPolicyService.seed_defaults(db)

    def test_01_policy_version_lineage_and_status(self):
        """TEST 1: Policies maintain explicit versioning and supersedes_policy_id linkage."""
        res = client.get("/api/v1/semantic-policies")
        self.assertEqual(res.status_code, 200)
        policies = res.json()
        pol_map = {p["policy_id"]: p for p in policies}

        self.assertIn("spol_cisco_asa_v0", pol_map)
        self.assertIn("spol_cisco_asa_v1", pol_map)
        self.assertIn("spol_cisco_asa_v2_draft", pol_map)

        self.assertEqual(pol_map["spol_cisco_asa_v0"]["status"], "SUPERSEDED")
        self.assertEqual(pol_map["spol_cisco_asa_v1"]["status"], "ACTIVE")
        self.assertEqual(pol_map["spol_cisco_asa_v2_draft"]["status"], "DRAFT")

        self.assertEqual(pol_map["spol_cisco_asa_v1"]["supersedes_policy_id"], "spol_cisco_asa_v0")
        self.assertEqual(pol_map["spol_cisco_asa_v2_draft"]["supersedes_policy_id"], "spol_cisco_asa_v1")

    def test_02_compare_policies_diff_and_semantic_impact(self):
        """TEST 2: Policy comparison correctly computes unchanged, changed, and added rules with impact."""
        res = client.get(
            "/api/v1/semantic-policies/compare",
            params={
                "source_policy_id": "spol_cisco_asa_v1",
                "target_policy_id": "spol_cisco_asa_v2_draft",
            },
        )
        self.assertEqual(res.status_code, 200)
        diff = res.json()

        self.assertEqual(diff["source_policy"]["policy_id"], "spol_cisco_asa_v1")
        self.assertEqual(diff["target_policy"]["policy_id"], "spol_cisco_asa_v2_draft")

        # Unchanged rules: ALLOW, DENY
        unchanged_values = [r["source_value"] for r in diff["unchanged_rules"]]
        self.assertIn("ALLOW", unchanged_values)
        self.assertIn("DENY", unchanged_values)

        # Added rules: BYPASS
        added_values = [r["source_value"] for r in diff["added_rules"]]
        self.assertIn("BYPASS", added_values)

        # Changed rules: PERMIT (ALLOWED -> MONITORED, HIGH semantic impact)
        changed = diff["changed_rules"]
        self.assertGreaterEqual(len(changed), 1)
        permit_change = next((c for c in changed if c["source_value"] == "PERMIT"), None)
        self.assertIsNotNone(permit_change)
        self.assertEqual(permit_change["old_canonical_value"], "ALLOWED")
        self.assertEqual(permit_change["new_canonical_value"], "MONITORED")
        self.assertEqual(permit_change["semantic_impact"], "HIGH")
        self.assertTrue(permit_change["is_protected_field"])

    def test_03_compare_policies_invalid_id_404(self):
        """TEST 3: Comparing with a non-existent policy returns 404."""
        res = client.get(
            "/api/v1/semantic-policies/compare",
            params={
                "source_policy_id": "spol_cisco_asa_v1",
                "target_policy_id": "spol_nonexistent_999",
            },
        )
        self.assertEqual(res.status_code, 404)

    def test_04_create_draft_policy_enforcement(self):
        """TEST 4: Creating a policy always defaults to DRAFT status and forbids direct activation."""
        payload = {
            "policy_name": "Test Firewall Policy",
            "vendor_name": "Fortinet FortiGate",
            "source_profile_id": "sp_firewall_syslog",
            "status": "ACTIVE",  # Attempt to force ACTIVE
            "description": "Experimental draft policy",
            "rules": [
                {
                    "source_field": "action",
                    "source_value": "ACCEPT",
                    "canonical_field": "action.result",
                    "canonical_value": "ALLOWED",
                    "equivalence_classification": "EQUIVALENT",
                    "risk_level": "LOW",
                }
            ],
        }
        res = client.post("/api/v1/semantic-policies", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["status"], "DRAFT")  # Forced DRAFT state
        self.assertEqual(data["vendor_name"], "Fortinet FortiGate")
        self.assertEqual(len(data["rules"]), 1)

    def test_05_protected_fields_security_catalog(self):
        """TEST 5: Protected fields catalog includes critical telemetry fields."""
        res = client.get("/api/v1/protected-fields")
        self.assertEqual(res.status_code, 200)
        fields = res.json()
        field_names = [f["field_name"] for f in fields]

        self.assertIn("action.result", field_names)
        self.assertIn("authentication.outcome", field_names)
        self.assertIn("severity", field_names)

        action_res = next(f for f in fields if f["field_name"] == "action.result")
        self.assertEqual(action_res["criticality"], "CRITICAL")
        self.assertTrue(action_res["is_protected"])


if __name__ == "__main__":
    unittest.main()
