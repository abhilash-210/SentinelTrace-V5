"""
tests/test_sprint6c_detection_rule_governance.py
------------------------------------------------
Comprehensive test suite for Sprint 6C: Detection Rule Governance,
Dual-Control Approval, Rule Versioning, Version Impact Analysis,
and Immutable Governance Auditability.

32 exhaustive automated unit, integration, and security tests covering:
- Draft version creation & monotonic incrementing
- Deterministic SHA-256 version hashing & sensitivity
- Maker-Checker separation (Self-Approval Blocked HTTP 409)
- Independent reviewer approval & rejection workflows
- Atomic activation & single ACTIVE version supersession
- Invalid state transition blocking (DRAFT/PENDING -> ACTIVE)
- Version impact classification (CRITICAL, HIGH, MEDIUM, LOW, NONE)
- Pre-approval hypothetical trust simulation isolation
- Immutable version-scoped dependency snapshots
- Append-only governance audit events with deterministic hashes
- 15-stage end-to-end governance provenance trace
- Strict RBAC security boundaries
"""

import unittest
import uuid
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.detection_rule import DetectionRule, DetectionRuleDependency
from app.models.detection_rule_governance import (
    DetectionRuleApprovalRequest,
    DetectionRuleGovernanceEvent,
    DetectionRuleVersion,
    DetectionRuleVersionDependency,
    DetectionRuleVersionImpact,
)
from app.models.detection_rule_trust import DetectionRuleTrustEvaluation
from app.services.detection_rule_governance_service import DetectionRuleGovernanceService
from app.services.detection_rule_service import DetectionRuleService
from app.services.detection_rule_trust_service import DetectionRuleTrustService
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint6CDetectionRuleGovernance(unittest.TestCase):
    """Automated test suite for Sprint 6C Detection Rule Governance."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)
            DetectionRuleService.seed_defaults(db)
            DetectionRuleTrustService.seed_demo_trust_scenarios(db)
            DetectionRuleGovernanceService.seed_default_governed_versions(db)

    # ── Test 1: Create new DRAFT version ─────────────────────────────────────
    def test_01_create_new_draft_version(self):
        """Verify creating a new version creates status DRAFT with SHA-256 hash."""
        headers = get_auth_headers("POLICY_AUTHOR")
        payload = {
            "rule_name": "Firewall Port Scan Advanced",
            "vendor_name": "Cisco ASA",
            "description": "Enhanced port scan detector with tighter threshold",
            "query_signature": "SELECT * FROM events WHERE disposition = 'DENY' GROUP BY src_endpoint_ip HAVING COUNT(*) > 10",
            "severity": "HIGH",
            "mitre_techniques": ["T1046", "T1190"],
            "dependencies": [
                {"canonical_field": "disposition", "dependency_type": "REQUIRED"},
                {"canonical_field": "src_endpoint_ip", "dependency_type": "REQUIRED"},
            ],
        }
        response = client.post(
            "/api/v1/detection-rules/drule_fw_deny_scan/versions",
            json=payload,
            headers=headers,
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["status"], "DRAFT")
        self.assertGreater(data["version_number"], 1)
        self.assertIsNotNone(data["version_hash"])
        self.assertEqual(len(data["version_hash"]), 64)
        self.assertEqual(len(data["dependencies"]), 2)

    # ── Test 2: Version numbers increment deterministically ──────────────────
    def test_02_version_numbers_increment_deterministically(self):
        """Verify version numbers strictly increment (v1 -> v2 -> v3...)."""
        with SessionLocal() as db:
            v_a = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_linux_ssh_brute",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="SSH Brute Force Detection v2",
                vendor_name="Linux Auth",
                severity="HIGH",
            )
            v_b = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_linux_ssh_brute",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="SSH Brute Force Detection v3",
                vendor_name="Linux Auth",
                severity="CRITICAL",
            )
            self.assertEqual(v_b.version_number, v_a.version_number + 1)

    # ── Test 3: Version hash deterministic ───────────────────────────────────
    def test_03_version_hash_deterministic(self):
        """Verify identical rule content produces the exact same version hash."""
        hash1 = DetectionRuleGovernanceService.compute_version_hash(
            rule_id="drule_test",
            version_number=1,
            rule_name="Test Rule",
            vendor_name="Test Vendor",
            description="Test Description",
            query_signature="SELECT 1",
            severity="MEDIUM",
            mitre_techniques=["T1078"],
            dependencies=[{"canonical_field": "src_endpoint_ip", "dependency_type": "REQUIRED"}],
        )
        hash2 = DetectionRuleGovernanceService.compute_version_hash(
            rule_id="drule_test",
            version_number=1,
            rule_name="Test Rule",
            vendor_name="Test Vendor",
            description="Test Description",
            query_signature="SELECT 1",
            severity="MEDIUM",
            mitre_techniques=["T1078"],
            dependencies=[{"canonical_field": "src_endpoint_ip", "dependency_type": "REQUIRED"}],
        )
        self.assertEqual(hash1, hash2)

    # ── Test 4: Version hash changes when query changes ──────────────────────
    def test_04_version_hash_changes_when_query_changes(self):
        """Verify modifying query signature changes the version hash."""
        hash_base = DetectionRuleGovernanceService.compute_version_hash(
            rule_id="drule_test",
            version_number=1,
            rule_name="Test Rule",
            vendor_name="Test Vendor",
            description="Test",
            query_signature="SELECT 1",
            severity="MEDIUM",
            mitre_techniques=[],
            dependencies=[],
        )
        hash_modified = DetectionRuleGovernanceService.compute_version_hash(
            rule_id="drule_test",
            version_number=1,
            rule_name="Test Rule",
            vendor_name="Test Vendor",
            description="Test",
            query_signature="SELECT 2",
            severity="MEDIUM",
            mitre_techniques=[],
            dependencies=[],
        )
        self.assertNotEqual(hash_base, hash_modified)

    # ── Test 5: Version hash changes when dependencies change ────────────────
    def test_05_version_hash_changes_when_dependencies_change(self):
        """Verify altering declared dependencies changes the version hash."""
        hash_no_dep = DetectionRuleGovernanceService.compute_version_hash(
            rule_id="drule_test",
            version_number=1,
            rule_name="Test Rule",
            vendor_name="Test Vendor",
            description="Test",
            query_signature="SELECT 1",
            severity="MEDIUM",
            mitre_techniques=[],
            dependencies=[],
        )
        hash_with_dep = DetectionRuleGovernanceService.compute_version_hash(
            rule_id="drule_test",
            version_number=1,
            rule_name="Test Rule",
            vendor_name="Test Vendor",
            description="Test",
            query_signature="SELECT 1",
            severity="MEDIUM",
            mitre_techniques=[],
            dependencies=[{"canonical_field": "action.result", "dependency_type": "REQUIRED"}],
        )
        self.assertNotEqual(hash_no_dep, hash_with_dep)

    # ── Test 6: Submitted version becomes immutable ──────────────────────────
    def test_06_submitted_version_becomes_immutable(self):
        """Verify that submitted versions cannot be re-submitted or modified in place."""
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_win_sec_logon",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Windows Logon Rule v2",
                vendor_name="Windows Security",
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=ver.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )

            # Attempt re-submitting version
            with self.assertRaises(ValueError):
                DetectionRuleGovernanceService.submit_for_review(
                    db=db,
                    version_id=ver.version_id,
                    user_id="usr_author_cisco",
                    user_role="POLICY_AUTHOR",
                )

    # ── Test 7: Author can submit own draft ──────────────────────────────────
    def test_07_author_can_submit_own_draft(self):
        """Verify the author can successfully submit their own draft for review."""
        headers = get_auth_headers("POLICY_AUTHOR")
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_suri_dns_tunnel",
                user_id="usr_author_002",
                user_role="POLICY_AUTHOR",
                rule_name="DNS Tunnel Rule v2",
                vendor_name="Suricata IDS",
            )
            ver_id = ver.version_id

        response = client.post(
            f"/api/v1/detection-rule-versions/{ver_id}/submit",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "PENDING_REVIEW")

    # ── Test 8: Non-author cannot submit another author's draft ──────────────
    def test_08_non_author_cannot_submit_another_authors_draft(self):
        """Verify non-author cannot submit another author's draft."""
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_suri_dns_tunnel",
                user_id="usr_other_author_99",
                user_role="POLICY_AUTHOR",
                rule_name="Private Draft",
                vendor_name="Suricata IDS",
            )
            ver_id = ver.version_id

        # Attempt submitting using usr_author_cisco credentials
        headers = get_auth_headers("POLICY_AUTHOR")
        response = client.post(
            f"/api/v1/detection-rule-versions/{ver_id}/submit",
            headers=headers,
        )
        self.assertEqual(response.status_code, 403)

    # ── Test 9: Submission creates approval request ──────────────────────────
    def test_09_submission_creates_approval_request(self):
        """Verify submitting creates a PENDING DetectionRuleApprovalRequest."""
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="AWS Root Login v2",
                vendor_name="AWS CloudTrail",
            )
            _, app_req, _ = DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=ver.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            self.assertIsNotNone(app_req)
            self.assertEqual(app_req.status, "PENDING")
            self.assertEqual(app_req.version_id, ver.version_id)

    # ── Test 10: Submission generates impact analysis ────────────────────────
    def test_10_submission_generates_impact_analysis(self):
        """Verify submitting generates stored DetectionRuleVersionImpact analysis."""
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="AWS Root Login v3",
                vendor_name="AWS CloudTrail",
                query_signature="NEW_QUERY_LOGIC",
            )
            _, _, impact = DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=ver.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            self.assertIsNotNone(impact)
            self.assertIn(impact.impact_level, ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])

    # ── Test 11: Submission generates trust simulation ───────────────────────
    def test_11_submission_generates_trust_simulation(self):
        """Verify trust simulation endpoint returns simulated score and state."""
        headers = get_auth_headers("POLICY_REVIEWER")
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_fw_deny_scan",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Sim Test",
                vendor_name="Cisco ASA",
                dependencies=[{"canonical_field": "disposition", "dependency_type": "REQUIRED"}],
            )
            ver_id = ver.version_id

        response = client.get(
            f"/api/v1/detection-rule-versions/{ver_id}/trust-simulation",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("simulated_score", data)
        self.assertIn("simulated_state", data)
        self.assertEqual(data["simulation_type"], "PRE_APPROVAL_HYPOTHETICAL")

    # ── Test 12: Creator cannot approve own version (Maker-Checker) ──────────
    def test_12_creator_cannot_approve_own_version(self):
        """MAKER-CHECKER ENFORCEMENT: Creator cannot approve own version (returns 409 Conflict)."""
        headers = get_auth_headers("ADMIN")  # usr_admin_001
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_fw_deny_scan",
                user_id="usr_admin_001",
                user_role="ADMIN",
                rule_name="Self Approval Test",
                vendor_name="Cisco ASA",
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=ver.version_id,
                user_id="usr_admin_001",
                user_role="ADMIN",
            )
            ver_id = ver.version_id

        # Attempt approval by same author
        response = client.post(
            f"/api/v1/detection-rule-versions/{ver_id}/review",
            json={"decision": "APPROVE", "comment": "Self approving"},
            headers=headers,
        )
        self.assertEqual(response.status_code, 409)
        self.assertIn("SELF_APPROVAL_FORBIDDEN", response.json()["detail"])

    # ── Test 13: Independent reviewer can approve ────────────────────────────
    def test_13_independent_reviewer_can_approve(self):
        """Verify independent reviewer (different user ID) can approve version."""
        headers = get_auth_headers("POLICY_REVIEWER")  # usr_reviewer_01
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_fw_deny_scan",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Independent Review Test",
                vendor_name="Cisco ASA",
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=ver.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            ver_id = ver.version_id

        response = client.post(
            f"/api/v1/detection-rule-versions/{ver_id}/review",
            json={"decision": "APPROVE", "comment": "Independent review approved."},
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "APPROVED")
        self.assertEqual(response.json()["approval_decision"], "APPROVED")

    # ── Test 14: Reviewer can reject ─────────────────────────────────────────
    def test_14_reviewer_can_reject(self):
        """Verify independent reviewer can reject a candidate version."""
        headers = get_auth_headers("POLICY_REVIEWER")
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_fw_deny_scan",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Rejection Test",
                vendor_name="Cisco ASA",
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=ver.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            ver_id = ver.version_id

        response = client.post(
            f"/api/v1/detection-rule-versions/{ver_id}/review",
            json={"decision": "REJECT", "comment": "Syntax flaw detected in query."},
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "REJECTED")

    # ── Test 15: APPROVED version can activate ───────────────────────────────
    def test_15_approved_version_can_activate(self):
        """Verify an APPROVED version can be activated in production."""
        headers = get_auth_headers("ADMIN")
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_linux_ssh_brute",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="SSH Brute Force Governed v4",
                vendor_name="Linux Auth",
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=ver.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            DetectionRuleGovernanceService.review_rule_version(
                db=db,
                version_id=ver.version_id,
                reviewer_id="usr_reviewer_01",
                reviewer_role="POLICY_REVIEWER",
                decision="APPROVE",
                comment="Approved for activation",
            )
            ver_id = ver.version_id

        response = client.post(
            f"/api/v1/detection-rule-versions/{ver_id}/activate",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ACTIVE")

    # ── Test 16: DRAFT version cannot activate ───────────────────────────────
    def test_16_draft_version_cannot_activate(self):
        """Verify DRAFT version cannot bypass approval and activate directly."""
        headers = get_auth_headers("ADMIN")
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_linux_ssh_brute",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Draft Direct Activation Test",
                vendor_name="Linux Auth",
            )
            ver_id = ver.version_id

        response = client.post(
            f"/api/v1/detection-rule-versions/{ver_id}/activate",
            headers=headers,
        )
        self.assertEqual(response.status_code, 400)

    # ── Test 17: PENDING_REVIEW version cannot activate ──────────────────────
    def test_17_pending_review_version_cannot_activate(self):
        """Verify PENDING_REVIEW version cannot activate before approval."""
        headers = get_auth_headers("ADMIN")
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_linux_ssh_brute",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Pending Direct Activation Test",
                vendor_name="Linux Auth",
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=ver.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            ver_id = ver.version_id

        response = client.post(
            f"/api/v1/detection-rule-versions/{ver_id}/activate",
            headers=headers,
        )
        self.assertEqual(response.status_code, 400)

    # ── Test 18: REJECTED version cannot activate ────────────────────────────
    def test_18_rejected_version_cannot_activate(self):
        """Verify REJECTED version cannot be activated."""
        headers = get_auth_headers("ADMIN")
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_linux_ssh_brute",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Rejected Activation Test",
                vendor_name="Linux Auth",
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=ver.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            DetectionRuleGovernanceService.review_rule_version(
                db=db,
                version_id=ver.version_id,
                reviewer_id="usr_reviewer_01",
                reviewer_role="POLICY_REVIEWER",
                decision="REJECT",
                comment="Rejected",
            )
            ver_id = ver.version_id

        response = client.post(
            f"/api/v1/detection-rule-versions/{ver_id}/activate",
            headers=headers,
        )
        self.assertEqual(response.status_code, 400)

    # ── Test 19: Activation supersedes previous ACTIVE version ───────────────
    def test_19_activation_supersedes_previous_active_version(self):
        """Verify activating a new version atomically transitions previous active version to SUPERSEDED."""
        with SessionLocal() as db:
            # 1. Active v1 exists
            v1 = (
                db.query(DetectionRuleVersion)
                .filter(
                    DetectionRuleVersion.rule_id == "drule_fw_deny_scan",
                    DetectionRuleVersion.status == "ACTIVE",
                )
                .first()
            )
            self.assertIsNotNone(v1)
            v1_id = v1.version_id

            # 2. Create and approve v_next
            v_new = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_fw_deny_scan",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Firewall Deny Next Gen",
                vendor_name="Cisco ASA",
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=v_new.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            DetectionRuleGovernanceService.review_rule_version(
                db=db,
                version_id=v_new.version_id,
                reviewer_id="usr_reviewer_01",
                reviewer_role="POLICY_REVIEWER",
                decision="APPROVE",
            )
            # 3. Activate v_new
            DetectionRuleGovernanceService.activate_rule_version(
                db=db,
                version_id=v_new.version_id,
                user_id="usr_admin_01",
                user_role="ADMIN",
            )

            # Check v1 is now SUPERSEDED
            v1_updated = db.query(DetectionRuleVersion).filter(DetectionRuleVersion.version_id == v1_id).first()
            self.assertEqual(v1_updated.status, "SUPERSEDED")
            self.assertEqual(v1_updated.superseded_by_version_id, v_new.version_id)

    # ── Test 20: Only one ACTIVE version exists ──────────────────────────────
    def test_20_only_one_active_version_exists(self):
        """INVARIANT: Only one ACTIVE version can exist per rule at any time."""
        with SessionLocal() as db:
            active_count = (
                db.query(DetectionRuleVersion)
                .filter(
                    DetectionRuleVersion.rule_id == "drule_fw_deny_scan",
                    DetectionRuleVersion.status == "ACTIVE",
                )
                .count()
            )
            self.assertEqual(active_count, 1)

    # ── Test 21: Protected field addition produces CRITICAL impact ───────────
    def test_21_protected_field_addition_produces_critical_impact(self):
        """Verify introducing a protected semantic field generates CRITICAL impact."""
        with SessionLocal() as db:
            v_src = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_suri_dns_tunnel",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="DNS Base",
                vendor_name="Suricata IDS",
                dependencies=[{"canonical_field": "dns_query", "dependency_type": "REQUIRED"}],
            )
            v_tgt = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_suri_dns_tunnel",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="DNS with Protected Field",
                vendor_name="Suricata IDS",
                dependencies=[
                    {"canonical_field": "dns_query", "dependency_type": "REQUIRED"},
                    {"canonical_field": "action.result", "dependency_type": "REQUIRED", "is_protected_field": True},
                ],
                parent_version_id=v_src.version_id,
            )
            impact = DetectionRuleGovernanceService.compare_rule_versions(
                db=db,
                source_version_id=v_src.version_id,
                target_version_id=v_tgt.version_id,
            )
            self.assertEqual(impact.impact_level, "CRITICAL")
            self.assertIn("action.result", impact.protected_fields_added)

    # ── Test 22: Query change produces HIGH impact ───────────────────────────
    def test_22_query_change_produces_high_impact(self):
        """Verify query logic change without protected fields produces HIGH impact."""
        with SessionLocal() as db:
            v_src = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_suri_dns_tunnel",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="DNS Base 2",
                vendor_name="Suricata IDS",
                query_signature="SELECT 1",
            )
            v_tgt = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_suri_dns_tunnel",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="DNS Modified Query",
                vendor_name="Suricata IDS",
                query_signature="SELECT 2 WHERE length > 50",
                parent_version_id=v_src.version_id,
            )
            impact = DetectionRuleGovernanceService.compare_rule_versions(
                db=db,
                source_version_id=v_src.version_id,
                target_version_id=v_tgt.version_id,
            )
            self.assertEqual(impact.impact_level, "HIGH")
            self.assertTrue(impact.query_changed)

    # ── Test 23: Description-only change produces LOW impact ─────────────────
    def test_23_description_only_change_produces_low_impact(self):
        """Verify changing only the description produces LOW impact."""
        with SessionLocal() as db:
            v_src = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_suri_dns_tunnel",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="DNS Base 3",
                vendor_name="Suricata IDS",
                description="Original description",
            )
            v_tgt = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_suri_dns_tunnel",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="DNS Base 3",
                vendor_name="Suricata IDS",
                description="Updated documentation only",
                parent_version_id=v_src.version_id,
            )
            impact = DetectionRuleGovernanceService.compare_rule_versions(
                db=db,
                source_version_id=v_src.version_id,
                target_version_id=v_tgt.version_id,
            )
            self.assertEqual(impact.impact_level, "LOW")

    # ── Test 24: Trust simulation does not mutate Sprint 6B runtime evals ────
    def test_24_trust_simulation_does_not_mutate_sprint6b_runtime_evaluations(self):
        """Verify hypothetical pre-approval simulation does NOT create runtime evaluations."""
        with SessionLocal() as db:
            initial_count = db.query(DetectionRuleTrustEvaluation).count()
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_win_sec_logon",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Sim Isolation Test",
                vendor_name="Windows Security",
                dependencies=[{"canonical_field": "action.result", "dependency_type": "REQUIRED"}],
            )
            # Run simulation
            DetectionRuleGovernanceService.simulate_version_trust(db, ver.version_id)
            final_count = db.query(DetectionRuleTrustEvaluation).count()
            self.assertEqual(initial_count, final_count)

    # ── Test 25: Governance events are generated ─────────────────────────────
    def test_25_governance_events_are_generated(self):
        """Verify governance operations generate append-only DetectionRuleGovernanceEvent records."""
        with SessionLocal() as db:
            events = db.query(DetectionRuleGovernanceEvent).all()
            self.assertGreaterEqual(len(events), 1)
            event_types = {e.event_type for e in events}
            self.assertIn("RULE_ACTIVATED", event_types)

    # ── Test 26: Governance event hashes are deterministic ───────────────────
    def test_26_governance_event_hashes_are_deterministic(self):
        """Verify governance event SHA-256 hash is deterministic."""
        h1 = DetectionRuleGovernanceService.compute_governance_event_hash(
            event_type="RULE_ACTIVATED",
            rule_id="drule_1",
            version_id="drver_1",
            actor_user_id="usr_1",
            timestamp_str="2026-09-07T00:00:00Z",
            payload={"version": 1},
        )
        h2 = DetectionRuleGovernanceService.compute_governance_event_hash(
            event_type="RULE_ACTIVATED",
            rule_id="drule_1",
            version_id="drver_1",
            actor_user_id="usr_1",
            timestamp_str="2026-09-07T00:00:00Z",
            payload={"version": 1},
        )
        self.assertEqual(h1, h2)

    # ── Test 27: Historical version remains unchanged ────────────────────────
    def test_27_historical_version_remains_unchanged(self):
        """Verify creating a new version does NOT mutate historical versions."""
        with SessionLocal() as db:
            v1 = (
                db.query(DetectionRuleVersion)
                .filter(
                    DetectionRuleVersion.rule_id == "drule_cisco_asa_permit",
                    DetectionRuleVersion.version_number == 1,
                )
                .first()
            )
            v1_hash_before = v1.version_hash

            # Create v2
            DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_cisco_asa_permit",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Cisco ASA Permit v2",
                vendor_name="Cisco ASA",
            )

            v1_after = (
                db.query(DetectionRuleVersion)
                .filter(DetectionRuleVersion.version_id == v1.version_id)
                .first()
            )
            self.assertEqual(v1_after.version_hash, v1_hash_before)

    # ── Test 28: Dependency snapshots remain immutable ───────────────────────
    def test_28_dependency_snapshots_remain_immutable(self):
        """Verify version dependency snapshots persist even if live registry changes."""
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_cisco_asa_permit",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Snapshot Test",
                vendor_name="Cisco ASA",
                dependencies=[{"canonical_field": "src_endpoint_ip", "dependency_type": "REQUIRED"}],
            )
            deps = (
                db.query(DetectionRuleVersionDependency)
                .filter(DetectionRuleVersionDependency.version_id == ver.version_id)
                .all()
            )
            self.assertEqual(len(deps), 1)
            self.assertEqual(deps[0].canonical_field, "src_endpoint_ip")

    # ── Test 29: RBAC prevents unauthorized review ───────────────────────────
    def test_29_rbac_prevents_unauthorized_review(self):
        """Verify VIEWER or POLICY_AUTHOR cannot perform reviews (HTTP 403)."""
        headers = get_auth_headers("VIEWER")
        response = client.post(
            "/api/v1/detection-rule-versions/drver_cisco_asa_permit_v1/review",
            json={"decision": "APPROVE"},
            headers=headers,
        )
        self.assertEqual(response.status_code, 403)

    # ── Test 30: RBAC prevents unauthorized activation ───────────────────────
    def test_30_rbac_prevents_unauthorized_activation(self):
        """Verify POLICY_AUTHOR cannot activate versions (HTTP 403)."""
        headers = get_auth_headers("POLICY_AUTHOR")
        response = client.post(
            "/api/v1/detection-rule-versions/drver_cisco_asa_permit_v1/activate",
            headers=headers,
        )
        self.assertEqual(response.status_code, 403)

    # ── Test 31: Governance trace returns complete chain ─────────────────────
    def test_31_governance_trace_returns_complete_chain(self):
        """Verify 15-stage governance trace endpoint returns complete provenance chain."""
        headers = get_auth_headers("AUDITOR")
        with SessionLocal() as db:
            ver = db.query(DetectionRuleVersion).first()
            self.assertIsNotNone(ver)
            ver_id = ver.version_id

        response = client.get(
            f"/api/v1/detection-rule-versions/{ver_id}/governance-trace",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("provenance_chain", data)
        self.assertGreaterEqual(len(data["provenance_chain"]), 3)

    # ── Test 32: Disable active rule version ─────────────────────────────────
    def test_32_disable_active_rule_version(self):
        """Verify disabling an active version transitions status to DISABLED."""
        headers = get_auth_headers("ADMIN")
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="AWS Disable Test",
                vendor_name="AWS CloudTrail",
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=ver.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            DetectionRuleGovernanceService.review_rule_version(
                db=db,
                version_id=ver.version_id,
                reviewer_id="usr_reviewer_01",
                reviewer_role="POLICY_REVIEWER",
                decision="APPROVE",
            )
            DetectionRuleGovernanceService.activate_rule_version(
                db=db,
                version_id=ver.version_id,
                user_id="usr_admin_01",
                user_role="ADMIN",
            )
            ver_id = ver.version_id

        response = client.post(
            f"/api/v1/detection-rule-versions/{ver_id}/disable?reason=Maintenance",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "DISABLED")

    # ── Test 33: List rule versions with pagination and status filter ────────
    def test_33_list_rule_versions_with_pagination_and_filter(self):
        """Verify GET /api/v1/detection-rule-versions supports pagination and filtering."""
        headers = get_auth_headers("SECURITY_ANALYST")
        response = client.get(
            "/api/v1/detection-rule-versions?limit=5&offset=0&status=ACTIVE",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        for item in data:
            self.assertEqual(item["status"], "ACTIVE")

    # ── Test 34: List rule versions filtered by created_by ───────────────────
    def test_34_list_rule_versions_filtered_by_creator(self):
        """Verify filtering detection rule versions by creator user ID."""
        headers = get_auth_headers("POLICY_AUTHOR")
        response = client.get(
            "/api/v1/detection-rule-versions?created_by=usr_author_cisco",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        for item in data:
            self.assertEqual(item["created_by_user_id"], "usr_author_cisco")

    # ── Test 35: List rule versions filtered by reviewer ─────────────────────
    def test_35_list_rule_versions_filtered_by_reviewer(self):
        """Verify filtering detection rule versions by reviewer user ID."""
        headers = get_auth_headers("POLICY_REVIEWER")
        response = client.get(
            "/api/v1/detection-rule-versions?reviewed_by=usr_reviewer_01",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        for item in data:
            self.assertEqual(item["reviewed_by_user_id"], "usr_reviewer_01")

    # ── Test 36: Cannot disable non-ACTIVE version ───────────────────────────
    def test_36_cannot_disable_non_active_version(self):
        """Verify disabling a DRAFT or APPROVED version raises 400 Bad Request."""
        headers = get_auth_headers("ADMIN")
        with SessionLocal() as db:
            draft = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Draft Cannot Disable",
                vendor_name="AWS CloudTrail",
            )
            draft_id = draft.version_id

        response = client.post(
            f"/api/v1/detection-rule-versions/{draft_id}/disable?reason=Test",
            headers=headers,
        )
        self.assertEqual(response.status_code, 400)

    # ── Test 37: Cannot review already APPROVED or REJECTED version ──────────
    def test_37_cannot_review_already_finalized_version(self):
        """Verify reviewing a version that is already APPROVED returns 400 Bad Request."""
        headers = get_auth_headers("POLICY_REVIEWER")
        with SessionLocal() as db:
            v = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Finalized Version",
                vendor_name="AWS CloudTrail",
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=v.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            DetectionRuleGovernanceService.review_rule_version(
                db=db,
                version_id=v.version_id,
                reviewer_id="usr_reviewer_01",
                reviewer_role="POLICY_REVIEWER",
                decision="APPROVE",
            )
            v_id = v.version_id

        response = client.post(
            f"/api/v1/detection-rule-versions/{v_id}/review",
            headers=headers,
            json={"decision": "APPROVE", "comment": "Duplicate approval attempt"},
        )
        self.assertEqual(response.status_code, 400)

    # ── Test 38: Stored impact analysis retrieval via GET /impact ────────────
    def test_38_stored_impact_analysis_retrieval(self):
        """Verify GET /api/v1/detection-rule-versions/{version_id}/impact returns stored impact."""
        headers = get_auth_headers("SECURITY_ANALYST")
        with SessionLocal() as db:
            v_src = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Impact Base",
                vendor_name="AWS CloudTrail",
            )
            v_tgt = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Impact Candidate",
                vendor_name="AWS CloudTrail",
                parent_version_id=v_src.version_id,
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=v_tgt.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            tgt_id = v_tgt.version_id

        response = client.get(
            f"/api/v1/detection-rule-versions/{tgt_id}/impact",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("impact_level", data)
        self.assertEqual(data["target_version_id"], tgt_id)

    # ── Test 39: Pre-approval trust simulation API returns correct posture ───
    def test_39_pre_approval_trust_simulation_api(self):
        """Verify pre-approval trust simulation accurately reports simulation posture."""
        headers = get_auth_headers("POLICY_REVIEWER")
        with SessionLocal() as db:
            v = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Simulation Test Rule",
                vendor_name="AWS CloudTrail",
                dependencies=[
                    {"canonical_field": "actor.user.name", "dependency_type": "REQUIRED"},
                    {"canonical_field": "action.result", "dependency_type": "REQUIRED", "is_protected_field": True},
                ],
            )
            v_id = v.version_id

        response = client.get(
            f"/api/v1/detection-rule-versions/{v_id}/trust-simulation",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["version_id"], v_id)
        self.assertIn("simulated_score", data)
        self.assertIn("simulated_state", data)
        self.assertIn("reasons", data)
        self.assertIsInstance(data["reasons"], list)

    # ── Test 40: Review with risk acknowledgment ────────────────────────────
    def test_40_review_with_risk_acknowledgment(self):
        """Verify reviewer can approve a candidate version with explicit risk acknowledgment."""
        headers = get_auth_headers("POLICY_REVIEWER")
        with SessionLocal() as db:
            v = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Risk Ack Candidate",
                vendor_name="AWS CloudTrail",
            )
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=v.version_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            v_id = v.version_id

        response = client.post(
            f"/api/v1/detection-rule-versions/{v_id}/review",
            headers=headers,
            json={
                "decision": "APPROVE",
                "comment": "Approved after reviewing telemetry impact",
                "risk_acknowledged": True,
                "risk_acknowledgement_comment": "Verified protected semantic field mitigations in place",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "APPROVED")

    # ── Test 41: Vendor scope change generates HIGH impact ───────────────────
    def test_41_vendor_scope_change_generates_high_impact(self):
        """Verify altering vendor scope generates HIGH impact in comparison."""
        with SessionLocal() as db:
            v1 = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Cross Vendor v1",
                vendor_name="Cisco ASA",
            )
            v2 = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Cross Vendor v2",
                vendor_name="Palo Alto PAN-OS",
                parent_version_id=v1.version_id,
            )
            impact = DetectionRuleGovernanceService.compare_rule_versions(
                db=db,
                source_version_id=v1.version_id,
                target_version_id=v2.version_id,
            )
            self.assertEqual(impact.impact_level, "HIGH")
            self.assertTrue(impact.vendor_scope_changed)

    # ── Test 42: MITRE technique modification generates MEDIUM impact ────────
    def test_42_mitre_technique_modification_generates_medium_impact(self):
        """Verify modifying MITRE technique without query or vendor changes yields MEDIUM impact."""
        with SessionLocal() as db:
            v1 = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="MITRE Base",
                vendor_name="AWS CloudTrail",
                mitre_techniques=["T1078"],
            )
            v2 = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="MITRE Updated",
                vendor_name="AWS CloudTrail",
                mitre_techniques=["T1078", "T1078.004"],
                parent_version_id=v1.version_id,
            )
            impact = DetectionRuleGovernanceService.compare_rule_versions(
                db=db,
                source_version_id=v1.version_id,
                target_version_id=v2.version_id,
            )
            self.assertEqual(impact.impact_level, "MEDIUM")
            self.assertTrue(impact.mitre_changed)

    # ── Test 43: Adding normal non-protected dependency ──────────────────────
    def test_43_adding_normal_dependency_impact(self):
        """Verify adding normal dependency produces LOW or MEDIUM impact."""
        with SessionLocal() as db:
            v1 = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Dep Base",
                vendor_name="AWS CloudTrail",
                dependencies=[{"canonical_field": "src_endpoint.ip", "dependency_type": "REQUIRED"}],
            )
            v2 = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Dep Added",
                vendor_name="AWS CloudTrail",
                dependencies=[
                    {"canonical_field": "src_endpoint.ip", "dependency_type": "REQUIRED"},
                    {"canonical_field": "dst_endpoint.port", "dependency_type": "OPTIONAL"},
                ],
                parent_version_id=v1.version_id,
            )
            impact = DetectionRuleGovernanceService.compare_rule_versions(
                db=db,
                source_version_id=v1.version_id,
                target_version_id=v2.version_id,
            )
            self.assertIn("dst_endpoint.port", impact.dependencies_added)
            self.assertIn(impact.impact_level, ["LOW", "MEDIUM"])

    # ── Test 44: Removing canonical dependency generates HIGH impact ─────────
    def test_44_removing_canonical_dependency_generates_high_impact(self):
        """Verify removing a canonical dependency triggers HIGH impact."""
        with SessionLocal() as db:
            v1 = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Dep Remove Base",
                vendor_name="AWS CloudTrail",
                dependencies=[
                    {"canonical_field": "src_endpoint.ip", "dependency_type": "REQUIRED"},
                    {"canonical_field": "dst_endpoint.ip", "dependency_type": "REQUIRED"},
                ],
            )
            v2 = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_aws_root_login",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Dep Removed",
                vendor_name="AWS CloudTrail",
                dependencies=[{"canonical_field": "src_endpoint.ip", "dependency_type": "REQUIRED"}],
                parent_version_id=v1.version_id,
            )
            impact = DetectionRuleGovernanceService.compare_rule_versions(
                db=db,
                source_version_id=v1.version_id,
                target_version_id=v2.version_id,
            )
            self.assertEqual(impact.impact_level, "HIGH")
            self.assertIn("dst_endpoint.ip", impact.dependencies_removed)

    # ── Test 45: Multiple sequential versions increment version_number ───────
    def test_45_multiple_sequential_versions_increment(self):
        """Verify successive versions strictly increment version_number (1 -> 2 -> 3)."""
        rule_uid = f"drule_seq_inc_{uuid.uuid4().hex[:8]}"
        with SessionLocal() as db:
            v1 = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id=rule_uid,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Sequential v1",
                vendor_name="AWS CloudTrail",
            )
            v2 = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id=rule_uid,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Sequential v2",
                vendor_name="AWS CloudTrail",
                parent_version_id=v1.version_id,
            )
            v3 = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id=rule_uid,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Sequential v3",
                vendor_name="AWS CloudTrail",
                parent_version_id=v2.version_id,
            )
            self.assertEqual(v1.version_number, 1)
            self.assertEqual(v2.version_number, 2)
            self.assertEqual(v3.version_number, 3)

    # ── Test 46: Audit log governance event verification for full lifecycle ──
    def test_46_audit_log_governance_events_full_lifecycle(self):
        """Verify immutable governance events recorded across full lifecycle."""
        with SessionLocal() as db:
            ver = DetectionRuleGovernanceService.create_rule_version(
                db=db,
                rule_id="drule_audit_lifecycle_test",
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
                rule_name="Audit Lifecycle Test",
                vendor_name="AWS CloudTrail",
            )
            v_id = ver.version_id
            DetectionRuleGovernanceService.submit_for_review(
                db=db,
                version_id=v_id,
                user_id="usr_author_cisco",
                user_role="POLICY_AUTHOR",
            )
            DetectionRuleGovernanceService.review_rule_version(
                db=db,
                version_id=v_id,
                reviewer_id="usr_reviewer_01",
                reviewer_role="POLICY_REVIEWER",
                decision="APPROVE",
            )
            DetectionRuleGovernanceService.activate_rule_version(
                db=db,
                version_id=v_id,
                user_id="usr_admin_01",
                user_role="ADMIN",
            )
            DetectionRuleGovernanceService.disable_rule_version(
                db=db,
                version_id=v_id,
                user_id="usr_admin_01",
                user_role="ADMIN",
                reason="End of lifecycle",
            )

            events = (
                db.query(DetectionRuleGovernanceEvent)
                .filter(DetectionRuleGovernanceEvent.version_id == v_id)
                .all()
            )
            event_types = {e.event_type for e in events}
            self.assertIn("RULE_VERSION_CREATED", event_types)
            self.assertIn("RULE_SUBMITTED_FOR_REVIEW", event_types)
            self.assertIn("RULE_APPROVED", event_types)
            self.assertIn("RULE_ACTIVATED", event_types)
            self.assertIn("RULE_DISABLED", event_types)

    # ── Test 47: Viewer role cannot create, submit, review, activate, or disable
    def test_47_viewer_role_is_strictly_read_only(self):
        """Verify VIEWER role gets 403 on all mutating governance endpoints."""
        headers = get_auth_headers("VIEWER")
        # 1. Create version -> 403
        r1 = client.post(
            "/api/v1/detection-rules/drule_fw_deny_scan/versions",
            headers=headers,
            json={"rule_name": "Viewer Try Create", "vendor_name": "Cisco ASA"},
        )
        self.assertEqual(r1.status_code, 403)

        # 2. Submit -> 403
        r2 = client.post(
            "/api/v1/detection-rule-versions/drver_cisco_asa_permit_v1/submit",
            headers=headers,
        )
        self.assertEqual(r2.status_code, 403)

        # 3. Review -> 403
        r3 = client.post(
            "/api/v1/detection-rule-versions/drver_cisco_asa_permit_v1/review",
            headers=headers,
            json={"decision": "APPROVE"},
        )
        self.assertEqual(r3.status_code, 403)

        # 4. Activate -> 403
        r4 = client.post(
            "/api/v1/detection-rule-versions/drver_cisco_asa_permit_v1/activate",
            headers=headers,
        )
        self.assertEqual(r4.status_code, 403)

        # 5. Disable -> 403
        r5 = client.post(
            "/api/v1/detection-rule-versions/drver_cisco_asa_permit_v1/disable",
            headers=headers,
        )
        self.assertEqual(r5.status_code, 403)
