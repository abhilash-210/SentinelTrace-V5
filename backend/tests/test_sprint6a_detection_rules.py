"""
tests/test_sprint6a_detection_rules.py
---------------------------------------
Test suite for Sprint 6A: Detection Rule Registry & Canonical Field
Dependency Mapping.

20 comprehensive unit, integration, and security tests covering:
- Detection rule creation (always DRAFT enforcement)
- Seed detection rules persistence
- Detection rule listing with filters
- Detection rule detail retrieval
- Canonical field dependency registration
- Canonical field impact analysis
- Dependency graph construction
- Known canonical field catalog
- RBAC permission enforcement
- Duplicate dependency idempotency
"""

import unittest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.detection_rule import DetectionRule, DetectionRuleDependency
from app.services.detection_rule_service import (
    CANONICAL_FIELDS,
    SEED_RULES,
    DetectionRuleService,
)
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint6ADetectionRules(unittest.TestCase):
    """Unit and Integration tests for Sprint 6A Detection Rule Registry."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)
            DetectionRuleService.seed_defaults(db)

    # ── Test 1: Seed Detection Rules Persisted ────────────────────────────────
    def test_01_seed_detection_rules_persisted(self):
        """Verify all seed detection rules are persisted in the database."""
        with SessionLocal() as db:
            rules = db.query(DetectionRule).all()
            self.assertGreaterEqual(len(rules), len(SEED_RULES))
            rule_ids = {r.rule_id for r in rules}
            for seed in SEED_RULES:
                self.assertIn(seed["rule_id"], rule_ids)

    # ── Test 2: Seed Rules Have Dependencies ──────────────────────────────────
    def test_02_seed_rules_have_dependencies(self):
        """Verify seed detection rules have associated canonical field dependencies."""
        with SessionLocal() as db:
            deps = db.query(DetectionRuleDependency).all()
            self.assertGreater(len(deps), 0)
            # Each seed rule has dependencies
            rule_ids_with_deps = {d.rule_id for d in deps}
            for seed in SEED_RULES:
                self.assertIn(seed["rule_id"], rule_ids_with_deps)

    # ── Test 3: Seed Idempotency ──────────────────────────────────────────────
    def test_03_seed_idempotency(self):
        """Verify re-seeding does not create duplicate rules."""
        with SessionLocal() as db:
            count_before = db.query(DetectionRule).count()
            DetectionRuleService.seed_defaults(db)
            count_after = db.query(DetectionRule).count()
            self.assertEqual(count_before, count_after)

    # ── Test 4: API List Detection Rules ──────────────────────────────────────
    def test_04_api_list_detection_rules(self):
        """GET /api/v1/detection-rules returns paginated rule list."""
        headers = get_auth_headers("ADMIN")
        resp = client.get("/api/v1/detection-rules", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total", data)
        self.assertIn("items", data)
        self.assertGreaterEqual(data["total"], len(SEED_RULES))

    # ── Test 5: API List With Status Filter ───────────────────────────────────
    def test_05_api_list_with_status_filter(self):
        """GET /api/v1/detection-rules?status=ACTIVE returns only active rules."""
        headers = get_auth_headers("ADMIN")
        resp = client.get("/api/v1/detection-rules?status=ACTIVE", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for item in data["items"]:
            self.assertEqual(item["status"], "ACTIVE")

    # ── Test 6: API List With Severity Filter ─────────────────────────────────
    def test_06_api_list_with_severity_filter(self):
        """GET /api/v1/detection-rules?severity=CRITICAL returns only critical rules."""
        headers = get_auth_headers("ADMIN")
        resp = client.get("/api/v1/detection-rules?severity=CRITICAL", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for item in data["items"]:
            self.assertEqual(item["severity"], "CRITICAL")

    # ── Test 7: API Get Rule Detail ───────────────────────────────────────────
    def test_07_api_get_rule_detail(self):
        """GET /api/v1/detection-rules/{rule_id} returns full rule with dependencies."""
        headers = get_auth_headers("ADMIN")
        resp = client.get("/api/v1/detection-rules/drule_fw_deny_scan", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["rule_id"], "drule_fw_deny_scan")
        self.assertEqual(data["vendor_name"], "Cisco ASA")
        self.assertGreater(data["dependency_count"], 0)
        self.assertGreater(len(data["dependencies"]), 0)

    # ── Test 8: API Get Rule Not Found ────────────────────────────────────────
    def test_08_api_get_rule_not_found(self):
        """GET /api/v1/detection-rules/{invalid} returns 404."""
        headers = get_auth_headers("ADMIN")
        resp = client.get("/api/v1/detection-rules/nonexistent_rule", headers=headers)
        self.assertEqual(resp.status_code, 404)

    # ── Test 9: API Create Rule Always DRAFT ──────────────────────────────────
    def test_09_api_create_rule_always_draft(self):
        """POST /api/v1/detection-rules creates rule in DRAFT status regardless of input."""
        headers = get_auth_headers("ADMIN")
        payload = {
            "rule_name": "Test DNS Exfiltration Rule",
            "vendor_name": "ANY",
            "description": "Detects suspicious DNS query patterns",
            "severity": "HIGH",
            "mitre_tactic": "TA0010: Exfiltration",
            "mitre_technique": "T1048: Exfiltration Over Alternative Protocol",
            "dependencies": [
                {"canonical_field": "dst_ip", "dependency_type": "REQUIRED", "description": "DNS server IP"},
                {"canonical_field": "dst_port", "dependency_type": "REQUIRED", "description": "Port 53"},
            ],
        }
        resp = client.post("/api/v1/detection-rules", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["status"], "DRAFT")
        self.assertTrue(data["rule_id"].startswith("drule_"))
        self.assertEqual(data["rule_name"], "Test DNS Exfiltration Rule")
        self.assertEqual(data["dependency_count"], 2)
        self.assertIsNotNone(data["created_by"])

    # ── Test 10: API Create Rule Without Dependencies ─────────────────────────
    def test_10_api_create_rule_without_dependencies(self):
        """POST /api/v1/detection-rules works without initial dependencies."""
        headers = get_auth_headers("SECURITY_ANALYST")
        payload = {
            "rule_name": "Bare Minimum Rule",
            "vendor_name": "Generic",
            "severity": "LOW",
        }
        resp = client.post("/api/v1/detection-rules", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["status"], "DRAFT")
        self.assertEqual(data["dependency_count"], 0)

    # ── Test 11: API Canonical Fields Catalog ─────────────────────────────────
    def test_11_api_canonical_fields_catalog(self):
        """GET /api/v1/detection-rules/canonical-fields returns known fields."""
        headers = get_auth_headers("ADMIN")
        resp = client.get("/api/v1/detection-rules/canonical-fields", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("canonical_fields", data)
        self.assertEqual(data["total"], len(CANONICAL_FIELDS))
        self.assertIn("action", data["canonical_fields"])
        self.assertIn("severity", data["canonical_fields"])

    # ── Test 12: API Field Impact Analysis ────────────────────────────────────
    def test_12_api_field_impact_analysis(self):
        """GET /api/v1/detection-rules/impact/{field} returns dependent rules."""
        headers = get_auth_headers("ADMIN")
        resp = client.get("/api/v1/detection-rules/impact/action", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["canonical_field"], "action")
        self.assertGreater(data["total_dependent_rules"], 0)
        self.assertIsInstance(data["impacted_rules"], list)
        # action is used by fw_deny_scan and brute_force
        rule_ids = [r["rule_id"] for r in data["impacted_rules"]]
        self.assertIn("drule_fw_deny_scan", rule_ids)
        self.assertIn("drule_brute_force", rule_ids)

    # ── Test 13: API Dependency Graph ─────────────────────────────────────────
    def test_13_api_dependency_graph(self):
        """GET /api/v1/detection-rules/dependency-graph returns nodes and edges."""
        headers = get_auth_headers("ADMIN")
        resp = client.get("/api/v1/detection-rules/dependency-graph", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertIn("total_rules", data)
        self.assertIn("total_fields", data)
        self.assertGreater(data["total_rules"], 0)
        self.assertGreater(data["total_fields"], 0)
        # Nodes should contain both rule and field types
        node_types = {n["type"] for n in data["nodes"]}
        self.assertIn("rule", node_types)
        self.assertIn("field", node_types)

    # ── Test 14: API Add Dependency to Existing Rule ──────────────────────────
    def test_14_api_add_dependency(self):
        """POST /api/v1/detection-rules/{id}/dependencies adds a new dependency."""
        headers = get_auth_headers("ADMIN")
        payload = {
            "canonical_field": "protocol",
            "dependency_type": "OPTIONAL",
            "description": "Protocol filter for scan refinement",
        }
        resp = client.post(
            "/api/v1/detection-rules/drule_fw_deny_scan/dependencies",
            json=payload,
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["canonical_field"], "protocol")
        self.assertEqual(data["dependency_type"], "OPTIONAL")

    # ── Test 15: API Add Dependency Idempotent ────────────────────────────────
    def test_15_api_add_dependency_idempotent(self):
        """POST duplicate dependency returns existing without error."""
        headers = get_auth_headers("ADMIN")
        payload = {
            "canonical_field": "action",
            "dependency_type": "REQUIRED",
            "description": "Already exists",
        }
        resp = client.post(
            "/api/v1/detection-rules/drule_fw_deny_scan/dependencies",
            json=payload,
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["canonical_field"], "action")

    # ── Test 16: API Add Dependency Rule Not Found ────────────────────────────
    def test_16_api_add_dependency_rule_not_found(self):
        """POST dependency to nonexistent rule returns 404."""
        headers = get_auth_headers("ADMIN")
        payload = {"canonical_field": "src_ip", "dependency_type": "REQUIRED"}
        resp = client.post(
            "/api/v1/detection-rules/nonexistent_rule/dependencies",
            json=payload,
            headers=headers,
        )
        self.assertEqual(resp.status_code, 404)

    # ── Test 17: RBAC Viewer Can Read Rules ───────────────────────────────────
    def test_17_rbac_viewer_can_read(self):
        """VIEWER role has DETECTION_RULE_READ permission."""
        headers = get_auth_headers("VIEWER")
        resp = client.get("/api/v1/detection-rules", headers=headers)
        self.assertEqual(resp.status_code, 200)

    # ── Test 18: RBAC Viewer Cannot Create Rules ──────────────────────────────
    def test_18_rbac_viewer_cannot_create(self):
        """VIEWER role lacks DETECTION_RULE_CREATE permission — HTTP 403."""
        headers = get_auth_headers("VIEWER")
        payload = {
            "rule_name": "Unauthorized Rule",
            "vendor_name": "ANY",
            "severity": "LOW",
        }
        resp = client.post("/api/v1/detection-rules", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 403)

    # ── Test 19: RBAC Unauthenticated Access Blocked ──────────────────────────
    def test_19_rbac_unauthenticated_blocked(self):
        """Unauthenticated request returns 401."""
        resp = client.get("/api/v1/detection-rules")
        self.assertEqual(resp.status_code, 401)

    # ── Test 20: MITRE ATT&CK Fields Preserved ───────────────────────────────
    def test_20_mitre_attack_fields_preserved(self):
        """Verify MITRE ATT&CK tactic and technique are preserved on seed rules."""
        headers = get_auth_headers("ADMIN")
        resp = client.get("/api/v1/detection-rules/drule_brute_force", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["mitre_tactic"], "TA0006: Credential Access")
        self.assertEqual(data["mitre_technique"], "T1110: Brute Force")
        self.assertEqual(data["severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
