"""
test_sprint3_semantic_registry.py
---------------------------------
Comprehensive automated test suite for Sprint 3A:
Semantic Policy Registry & Backend Management.

Tests:
1. Semantic policy seed data exists in database and API.
2. Cisco ASA semantic policy exists and is ACTIVE.
3. Demo Vendor semantic policy exists and is ACTIVE.
4. Same raw value 'PERMIT' maps differently across vendors (Cisco: ALLOWED, Demo Vendor: MONITORED).
5. No global mapping lookup is allowed; all rules strictly require vendor policy scoping.
6. Protected field 'action.result' exists and is classified as CRITICAL.
7. Protected field 'authentication.outcome' exists and is classified as CRITICAL.
8. Semantic policy rules belong to a specific policy and maintain strict relational integrity.
9. Newly registered policies default to DRAFT lifecycle status and reject unauthorized auto-activation.
10. Protected field 'severity' exists and is classified as HIGH.
"""

import unittest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.semantic_policy import (
    ProtectedSemanticField,
    SemanticPolicy,
    SemanticPolicyRule,
)
from app.services.semantic_policy_service import SemanticPolicyService
from tests.auth_helper import get_auth_headers

client = TestClient(app, headers=get_auth_headers("ADMIN"))


class TestSprint3SemanticRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            SemanticPolicyService.seed_defaults(db)

    def test_01_seed_policies_exist(self):
        """TEST 1: Semantic policy seed data exists in database and API."""
        response = client.get("/api/v1/semantic-policies")
        self.assertEqual(response.status_code, 200)
        policies = response.json()
        self.assertGreaterEqual(len(policies), 2)
        policy_ids = [p["policy_id"] for p in policies]
        self.assertIn("spol_cisco_asa_v1", policy_ids)
        self.assertIn("spol_demo_vendor_v1", policy_ids)

    def test_02_cisco_policy_is_active(self):
        """TEST 2: Cisco ASA policy is ACTIVE and contains valid structural linkage."""
        response = client.get("/api/v1/semantic-policies/spol_cisco_asa_v1")
        self.assertEqual(response.status_code, 200)
        policy = response.json()
        self.assertEqual(policy["policy_id"], "spol_cisco_asa_v1")
        self.assertEqual(policy["vendor_name"], "Cisco ASA")
        self.assertEqual(policy["status"], "ACTIVE")
        self.assertEqual(policy["version"], 1)
        self.assertGreaterEqual(len(policy["rules"]), 3)

    def test_03_demo_vendor_policy_is_active(self):
        """TEST 3: Demo Vendor policy is ACTIVE and contains valid structural linkage."""
        response = client.get("/api/v1/semantic-policies/spol_demo_vendor_v1")
        self.assertEqual(response.status_code, 200)
        policy = response.json()
        self.assertEqual(policy["policy_id"], "spol_demo_vendor_v1")
        self.assertEqual(policy["vendor_name"], "Demo Vendor")
        self.assertEqual(policy["status"], "ACTIVE")
        self.assertEqual(policy["version"], 1)
        self.assertGreaterEqual(len(policy["rules"]), 3)

    def test_04_same_raw_value_maps_differently_across_vendors(self):
        """
        TEST 4: Same raw value 'PERMIT' maps to different canonical meanings across vendors:
          - Cisco ASA:   PERMIT -> ALLOWED   (COMPATIBLE)
          - Demo Vendor: PERMIT -> MONITORED (AMBIGUOUS)
        """
        cisco_res = client.get("/api/v1/semantic-policies/spol_cisco_asa_v1")
        demo_res = client.get("/api/v1/semantic-policies/spol_demo_vendor_v1")
        self.assertEqual(cisco_res.status_code, 200)
        self.assertEqual(demo_res.status_code, 200)

        cisco_rules = {r["source_value"]: r for r in cisco_res.json()["rules"]}
        demo_rules = {r["source_value"]: r for r in demo_res.json()["rules"]}

        self.assertIn("PERMIT", cisco_rules)
        self.assertIn("PERMIT", demo_rules)

        # Cisco maps PERMIT to ALLOWED
        self.assertEqual(cisco_rules["PERMIT"]["canonical_value"], "ALLOWED")
        self.assertEqual(cisco_rules["PERMIT"]["canonical_field"], "action.result")
        self.assertEqual(cisco_rules["PERMIT"]["equivalence_classification"], "COMPATIBLE")

        # Demo Vendor maps PERMIT to MONITORED
        self.assertEqual(demo_rules["PERMIT"]["canonical_value"], "MONITORED")
        self.assertEqual(demo_rules["PERMIT"]["canonical_field"], "action.result")
        self.assertEqual(demo_rules["PERMIT"]["equivalence_classification"], "AMBIGUOUS")

        # Confirm distinct semantic interpretations
        self.assertNotEqual(
            cisco_rules["PERMIT"]["canonical_value"],
            demo_rules["PERMIT"]["canonical_value"],
        )

    def test_05_no_global_mapping_lookup_allowed(self):
        """
        TEST 5: Verify no unscoped global mapping table or global lookup API exists.
        All rules are accessible strictly through a policy context.
        """
        # Attempting to fetch non-existent global policy must return 404
        response = client.get("/api/v1/semantic-policies/spol_global")
        self.assertEqual(response.status_code, 404)

        with SessionLocal() as db:
            # Verify every rule in the DB has a valid, non-null parent policy_id
            rules = db.query(SemanticPolicyRule).all()
            self.assertGreater(len(rules), 0)
            for rule in rules:
                self.assertIsNotNone(rule.policy_id)
                self.assertTrue(rule.policy_id.startswith("spol_"))
                # Rule must link to an actual policy in the policies table
                parent = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == rule.policy_id).first()
                self.assertIsNotNone(parent)

    def test_06_protected_field_action_result_exists(self):
        """TEST 6: Protected field 'action.result' exists with CRITICAL criticality."""
        response = client.get("/api/v1/protected-fields")
        self.assertEqual(response.status_code, 200)
        fields = response.json()
        action_result = next((f for f in fields if f["field_name"] == "action.result"), None)
        self.assertIsNotNone(action_result)
        self.assertEqual(action_result["criticality"], "CRITICAL")
        self.assertTrue(action_result["is_protected"])

    def test_07_protected_field_authentication_outcome_exists(self):
        """TEST 7: Protected field 'authentication.outcome' exists with CRITICAL criticality."""
        response = client.get("/api/v1/protected-fields")
        self.assertEqual(response.status_code, 200)
        fields = response.json()
        auth_outcome = next((f for f in fields if f["field_name"] == "authentication.outcome"), None)
        self.assertIsNotNone(auth_outcome)
        self.assertEqual(auth_outcome["criticality"], "CRITICAL")
        self.assertTrue(auth_outcome["is_protected"])

    def test_08_semantic_policy_rules_belong_to_policy(self):
        """TEST 8: Semantic policy rules strictly belong to parent policy and cascade on delete."""
        with SessionLocal() as db:
            # Create a test policy with a rule
            test_pol = SemanticPolicy(
                policy_id="spol_test_rel_integrity",
                policy_name="Relational Integrity Test Policy",
                vendor_name="TestVendor",
                source_profile_id="sp_test",
                status="DRAFT",
            )
            db.add(test_pol)
            db.flush()

            test_rule = SemanticPolicyRule(
                rule_id="srule_test_rel_01",
                policy_id=test_pol.policy_id,
                source_field="status",
                source_value="OK",
                canonical_field="action.result",
                canonical_value="ALLOWED",
            )
            db.add(test_rule)
            db.commit()

            # Verify rule belongs to policy
            rule_db = db.query(SemanticPolicyRule).filter(SemanticPolicyRule.rule_id == "srule_test_rel_01").first()
            self.assertIsNotNone(rule_db)
            self.assertEqual(rule_db.policy_id, "spol_test_rel_integrity")

            # Delete policy and verify rule is cascaded
            db.delete(test_pol)
            db.commit()

            cascaded_rule = db.query(SemanticPolicyRule).filter(SemanticPolicyRule.rule_id == "srule_test_rel_01").first()
            self.assertIsNone(cascaded_rule)

    def test_09_new_policies_default_to_draft(self):
        """TEST 9: New policies default to DRAFT and cannot be initialized directly as ACTIVE."""
        payload = {
            "policy_name": "Palo Alto Firewall Policy",
            "vendor_name": "Palo Alto Networks",
            "source_profile_id": "sp_palo_alto_syslog",
            "status": "ACTIVE",  # Requesting ACTIVE must be overridden to DRAFT
            "description": "Initial draft for PAN-OS traffic logs",
            "rules": [
                {
                    "source_field": "action",
                    "source_value": "allow",
                    "canonical_field": "action.result",
                    "canonical_value": "ALLOWED",
                    "equivalence_classification": "EQUIVALENT",
                    "risk_level": "LOW",
                }
            ],
        }
        response = client.post("/api/v1/semantic-policies", json=payload)
        self.assertEqual(response.status_code, 201)
        created_policy = response.json()
        self.assertEqual(created_policy["status"], "DRAFT")  # Enforced DRAFT
        self.assertEqual(created_policy["vendor_name"], "Palo Alto Networks")
        self.assertEqual(created_policy["rule_count"], 1)

    def test_10_protected_field_severity_exists(self):
        """TEST 10: Protected field 'severity' exists with HIGH criticality."""
        response = client.get("/api/v1/protected-fields")
        self.assertEqual(response.status_code, 200)
        fields = response.json()
        severity_field = next((f for f in fields if f["field_name"] == "severity"), None)
        self.assertIsNotNone(severity_field)
        self.assertEqual(severity_field["criticality"], "HIGH")
        self.assertTrue(severity_field["is_protected"])


if __name__ == "__main__":
    unittest.main()
