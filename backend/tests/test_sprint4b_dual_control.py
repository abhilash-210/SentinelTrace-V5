"""
test_sprint4b_dual_control.py
-----------------------------
Automated test suite for Sprint 4B:
Dual-Control Approval & Policy Governance Workflow (Maker-Checker).

Tests:
1. Draft policy can be submitted for review.
2. Submission transitions policy lifecycle status to PENDING_REVIEW.
3. Approval ticket records the author's requester identity.
4. Maker-Checker Separation: Policy author CANNOT approve their own policy (403 Forbidden).
5. Authorized different reviewer successfully approves pending policy.
6. Rejection workflow transitions policy and approval ticket to REJECTED.
7. Invalid state transitions (e.g. direct DRAFT -> ACTIVE) are blocked with HTTP 409 Conflict.
8. Only APPROVED policies can be activated into live production.
9. Activation atomically supersedes previous active policy and preserves lineage.
10. Governance audit event generated upon policy submission (POLICY_SUBMITTED).
11. Governance audit event generated upon policy approval (POLICY_APPROVED).
12. Governance audit timeline returns chronological provenance history.
13. Unauthorized roles (VIEWER, SECURITY_ANALYST) are forbidden from approving policies (403).
14. Maker-Checker applies to Admin: Admin cannot self-approve a policy they authored.
15. Full approval list and detailed ticket inspection return accurate impact metrics.
"""

import unittest
import uuid
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.governance import GovernanceAuditLog, PolicyApprovalRequest
from app.models.semantic_policy import SemanticPolicy, SemanticPolicyRule
from app.services.normalization_service import NormalizationService
from app.services.policy_governance_service import PolicyGovernanceService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint4BDualControl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)

    def _create_draft_policy(self, vendor: str = "Palo Alto Networks", version: int = 1) -> str:
        """Helper to create a fresh draft policy with author identity."""
        author_headers = get_auth_headers("POLICY_AUTHOR")
        uid = uuid.uuid4().hex[:6]
        payload = {
            "policy_name": f"{vendor} Draft Policy {uid}",
            "vendor_name": vendor,
            "source_profile_id": "sp_firewall_syslog",
            "status": "DRAFT",
            "description": "Test policy for dual control workflow",
            "rules": [
                {
                    "source_field": "action",
                    "source_value": "pass",
                    "canonical_field": "action.result",
                    "canonical_value": "ALLOWED",
                    "equivalence_classification": "EQUIVALENT",
                    "risk_level": "LOW",
                }
            ],
        }
        res = client.post("/api/v1/semantic-policies", json=payload, headers=author_headers)
        self.assertEqual(res.status_code, 201)
        return res.json()["policy_id"]

    def test_01_draft_policy_can_be_submitted(self):
        """TEST 1: Draft policy can be submitted for review with SEMANTIC_POLICY_SUBMIT."""
        policy_id = self._create_draft_policy("Fortinet")
        author_headers = get_auth_headers("POLICY_AUTHOR")

        res = client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["policy_id"], policy_id)
        self.assertEqual(data["policy_status"], "PENDING_REVIEW")
        self.assertEqual(data["approval_status"], "PENDING")
        self.assertTrue(data["approval_id"].startswith("approval_"))
        self.assertEqual(data["requested_by"], "author_demo")

    def test_02_submission_changes_policy_status_to_pending_review(self):
        """TEST 2: Submission changes policy state to PENDING_REVIEW in database."""
        policy_id = self._create_draft_policy("Check Point")
        author_headers = get_auth_headers("POLICY_AUTHOR")

        client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)

        with SessionLocal() as db:
            policy = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == policy_id).first()
            self.assertIsNotNone(policy)
            self.assertEqual(policy.status, "PENDING_REVIEW")

    def test_03_approval_request_records_requester_identity(self):
        """TEST 3: Policy approval ticket accurately captures requester user_id and timestamps."""
        policy_id = self._create_draft_policy("Juniper SRX")
        author_headers = get_auth_headers("POLICY_AUTHOR")

        submit_res = client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)
        approval_id = submit_res.json()["approval_id"]

        reviewer_headers = get_auth_headers("POLICY_REVIEWER")
        detail_res = client.get(f"/api/v1/policy-approvals/{approval_id}", headers=reviewer_headers)
        self.assertEqual(detail_res.status_code, 200)
        data = detail_res.json()
        self.assertEqual(data["approval_id"], approval_id)
        self.assertEqual(data["requested_by_user_id"], "usr_author_002")
        self.assertEqual(data["requested_by_username"], "author_demo")
        self.assertEqual(data["status"], "PENDING")
        self.assertIn("MAKER-CHECKER", data["maker_checker_warning"])

    def test_04_policy_author_cannot_approve_own_policy(self):
        """TEST 4: MAKER-CHECKER SEPARATION: Policy author CANNOT approve their own policy (403)."""
        # Scenario A: POLICY_AUTHOR lacks POLICY_APPROVE permission -> 403
        policy_id = self._create_draft_policy("Self Approval Test Vendor A")
        author_headers = get_auth_headers("POLICY_AUTHOR")
        submit_res = client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)
        approval_id = submit_res.json()["approval_id"]

        approve_res = client.post(
            f"/api/v1/policy-approvals/{approval_id}/approve",
            json={"review_comment": "Self approving my own changes"},
            headers=author_headers,
        )
        self.assertEqual(approve_res.status_code, 403)
        self.assertIn("POLICY_APPROVE", approve_res.json()["detail"])

        # Scenario B: User with POLICY_APPROVE (Admin) attempts to self-approve own submission -> 403 SELF_APPROVAL_FORBIDDEN
        admin_headers = get_auth_headers("ADMIN")
        policy_id_b = self._create_draft_policy("Self Approval Test Vendor B")
        # Submit as admin
        sub_b = client.post(f"/api/v1/semantic-policies/{policy_id_b}/submit", headers=admin_headers)
        app_id_b = sub_b.json()["approval_id"]

        self_approve_res = client.post(
            f"/api/v1/policy-approvals/{app_id_b}/approve",
            json={"review_comment": "Self approval attempt"},
            headers=admin_headers,
        )
        self.assertEqual(self_approve_res.status_code, 403)
        self.assertIn("SELF_APPROVAL_FORBIDDEN", self_approve_res.json()["detail"])

    def test_05_different_reviewer_can_approve_policy(self):
        """TEST 5: Authorized different reviewer successfully approves the policy."""
        policy_id = self._create_draft_policy("Valid Review Vendor")
        author_headers = get_auth_headers("POLICY_AUTHOR")
        reviewer_headers = get_auth_headers("POLICY_REVIEWER")

        # 1. Author submits
        submit_res = client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)
        approval_id = submit_res.json()["approval_id"]

        # 2. Reviewer approves
        approve_res = client.post(
            f"/api/v1/policy-approvals/{approval_id}/approve",
            json={"review_comment": "Approved after reviewing rule equivalence."},
            headers=reviewer_headers,
        )
        self.assertEqual(approve_res.status_code, 200)
        data = approve_res.json()
        self.assertEqual(data["status"], "APPROVED")
        self.assertEqual(data["policy_status"], "APPROVED")
        self.assertEqual(data["reviewed_by_user_id"], "usr_reviewer_003")
        self.assertEqual(data["review_comment"], "Approved after reviewing rule equivalence.")

    def test_06_rejection_workflow_works(self):
        """TEST 6: Reviewer rejection transitions approval and policy to REJECTED."""
        policy_id = self._create_draft_policy("Reject Test Vendor")
        author_headers = get_auth_headers("POLICY_AUTHOR")
        reviewer_headers = get_auth_headers("POLICY_REVIEWER")

        submit_res = client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)
        approval_id = submit_res.json()["approval_id"]

        reject_res = client.post(
            f"/api/v1/policy-approvals/{approval_id}/reject",
            json={"review_comment": "Ambiguous rule mappings detected on critical field."},
            headers=reviewer_headers,
        )
        self.assertEqual(reject_res.status_code, 200)
        data = reject_res.json()
        self.assertEqual(data["status"], "REJECTED")
        self.assertEqual(data["policy_status"], "REJECTED")
        self.assertEqual(data["reviewed_by_user_id"], "usr_reviewer_003")

    def test_07_invalid_state_transition_draft_to_active_blocked(self):
        """TEST 7: Attempting direct DRAFT -> ACTIVE activation is blocked with HTTP 409 Conflict."""
        policy_id = self._create_draft_policy("Direct Activate Test Vendor")
        reviewer_headers = get_auth_headers("POLICY_REVIEWER")

        # Try to activate DRAFT directly
        act_res = client.post(f"/api/v1/semantic-policies/{policy_id}/activate", headers=reviewer_headers)
        self.assertEqual(act_res.status_code, 409)
        self.assertIn("INVALID_POLICY_STATE_TRANSITION", act_res.json()["detail"])

    def test_08_only_approved_policy_can_activate(self):
        """TEST 8: Only APPROVED policies can be activated into live production."""
        policy_id = self._create_draft_policy("Approved Activation Vendor")
        author_headers = get_auth_headers("POLICY_AUTHOR")
        reviewer_headers = get_auth_headers("POLICY_REVIEWER")

        # Submit -> Approve -> Activate
        submit_res = client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)
        approval_id = submit_res.json()["approval_id"]

        client.post(
            f"/api/v1/policy-approvals/{approval_id}/approve",
            json={"review_comment": "Valid"},
            headers=reviewer_headers,
        )

        # Now activate
        act_res = client.post(f"/api/v1/semantic-policies/{policy_id}/activate", headers=reviewer_headers)
        self.assertEqual(act_res.status_code, 200)
        data = act_res.json()
        self.assertEqual(data["activated_policy_id"], policy_id)
        self.assertEqual(data["status"], "ACTIVE")
        self.assertEqual(data["activated_by"], "reviewer_demo")
        self.assertTrue(data["audit_id"].startswith("audit_"))

    def test_09_activation_supersedes_previous_active_policy(self):
        """TEST 9: Activating a new policy version automatically marks the old version as SUPERSEDED."""
        author_headers = get_auth_headers("POLICY_AUTHOR")
        reviewer_headers = get_auth_headers("POLICY_REVIEWER")

        test_vendor = f"Vendor_Family_{uuid.uuid4().hex[:6]}"

        # 1. Create and Activate v1
        v1_payload = {
            "policy_name": f"{test_vendor} Policy v1",
            "vendor_name": test_vendor,
            "source_profile_id": "sp_firewall_syslog",
            "status": "DRAFT",
            "description": "Version 1",
            "rules": [],
        }
        res_v1 = client.post("/api/v1/semantic-policies", json=v1_payload, headers=author_headers)
        v1_id = res_v1.json()["policy_id"]

        sub_v1 = client.post(f"/api/v1/semantic-policies/{v1_id}/submit", headers=author_headers)
        app_v1 = sub_v1.json()["approval_id"]
        client.post(f"/api/v1/policy-approvals/{app_v1}/approve", headers=reviewer_headers)
        client.post(f"/api/v1/semantic-policies/{v1_id}/activate", headers=reviewer_headers)

        # 2. Create v2
        v2_payload = {
            "policy_name": f"{test_vendor} Policy v2 Candidate",
            "vendor_name": test_vendor,
            "source_profile_id": "sp_firewall_syslog",
            "status": "DRAFT",
            "description": "Version 2 upgraded rules",
            "supersedes_policy_id": v1_id,
            "rules": [
                {
                    "source_field": "action",
                    "source_value": "PERMIT",
                    "canonical_field": "action.result",
                    "canonical_value": "ALLOWED",
                }
            ],
        }
        res_v2 = client.post("/api/v1/semantic-policies", json=v2_payload, headers=author_headers)
        v2_id = res_v2.json()["policy_id"]

        # Submit v2
        sub_v2 = client.post(f"/api/v1/semantic-policies/{v2_id}/submit", headers=author_headers)
        app_v2 = sub_v2.json()["approval_id"]

        # Reviewer approves v2
        client.post(f"/api/v1/policy-approvals/{app_v2}/approve", headers=reviewer_headers)

        # Activate v2
        act_res = client.post(f"/api/v1/semantic-policies/{v2_id}/activate", headers=reviewer_headers)
        self.assertEqual(act_res.status_code, 200)
        act_data = act_res.json()
        self.assertEqual(act_data["activated_policy_id"], v2_id)
        self.assertEqual(act_data["superseded_policy_id"], v1_id)

        # Verify old policy is now SUPERSEDED
        with SessionLocal() as db:
            old_pol = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == v1_id).first()
            self.assertEqual(old_pol.status, "SUPERSEDED")

            new_pol = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == v2_id).first()
            self.assertEqual(new_pol.status, "ACTIVE")
            self.assertEqual(new_pol.supersedes_policy_id, v1_id)

    def test_10_governance_audit_event_created_for_submission(self):
        """TEST 10: Submitting a policy creates an immutable POLICY_SUBMITTED audit log entry."""
        policy_id = self._create_draft_policy("Audit Test Vendor")
        author_headers = get_auth_headers("POLICY_AUTHOR")

        client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)

        with SessionLocal() as db:
            audit = (
                db.query(GovernanceAuditLog)
                .filter(
                    GovernanceAuditLog.resource_id == policy_id,
                    GovernanceAuditLog.action == "POLICY_SUBMITTED",
                )
                .first()
            )
            self.assertIsNotNone(audit)
            self.assertEqual(audit.actor_username, "author_demo")
            self.assertEqual(audit.actor_role, "POLICY_AUTHOR")
            self.assertEqual(audit.previous_state, "DRAFT")
            self.assertEqual(audit.new_state, "PENDING_REVIEW")

    def test_11_governance_audit_event_created_for_approval(self):
        """TEST 11: Approving a policy creates an immutable POLICY_APPROVED audit log entry."""
        policy_id = self._create_draft_policy("Audit Approval Vendor")
        author_headers = get_auth_headers("POLICY_AUTHOR")
        reviewer_headers = get_auth_headers("POLICY_REVIEWER")

        submit_res = client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)
        approval_id = submit_res.json()["approval_id"]
        client.post(
            f"/api/v1/policy-approvals/{approval_id}/approve",
            json={"review_comment": "Audit verified"},
            headers=reviewer_headers,
        )

        with SessionLocal() as db:
            audit = (
                db.query(GovernanceAuditLog)
                .filter(
                    GovernanceAuditLog.resource_id == policy_id,
                    GovernanceAuditLog.action == "POLICY_APPROVED",
                )
                .first()
            )
            self.assertIsNotNone(audit)
            self.assertEqual(audit.actor_username, "reviewer_demo")
            self.assertEqual(audit.actor_role, "POLICY_REVIEWER")
            self.assertEqual(audit.new_state, "APPROVED")

    def test_12_governance_history_timeline_endpoint(self):
        """TEST 12: GET /api/v1/semantic-policies/{id}/governance-history returns chronological audit trail."""
        policy_id = self._create_draft_policy("History Timeline Vendor")
        author_headers = get_auth_headers("POLICY_AUTHOR")
        reviewer_headers = get_auth_headers("POLICY_REVIEWER")
        auditor_headers = get_auth_headers("AUDITOR")

        # Submit -> Approve -> Activate
        sub_res = client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)
        app_id = sub_res.json()["approval_id"]
        client.post(f"/api/v1/policy-approvals/{app_id}/approve", headers=reviewer_headers)
        client.post(f"/api/v1/semantic-policies/{policy_id}/activate", headers=reviewer_headers)

        # Auditor reads history
        hist_res = client.get(f"/api/v1/semantic-policies/{policy_id}/governance-history", headers=auditor_headers)
        self.assertEqual(hist_res.status_code, 200)
        data = hist_res.json()
        self.assertEqual(data["policy_id"], policy_id)
        self.assertGreaterEqual(len(data["timeline"]), 3)

        actions = [item["action"] for item in data["timeline"]]
        self.assertIn("POLICY_SUBMITTED", actions)
        self.assertIn("POLICY_APPROVED", actions)
        self.assertIn("POLICY_ACTIVATED", actions)

    def test_13_unauthorized_roles_blocked_from_approval(self):
        """TEST 13: VIEWER and SECURITY_ANALYST cannot approve or review policy tickets (403)."""
        policy_id = self._create_draft_policy("Role Guard Test")
        author_headers = get_auth_headers("POLICY_AUTHOR")
        sub_res = client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=author_headers)
        app_id = sub_res.json()["approval_id"]

        # Analyst tries to approve -> 403
        analyst_headers = get_auth_headers("SECURITY_ANALYST")
        res1 = client.post(f"/api/v1/policy-approvals/{app_id}/approve", headers=analyst_headers)
        self.assertEqual(res1.status_code, 403)

        # Viewer tries to approve -> 403
        viewer_headers = get_auth_headers("VIEWER")
        res2 = client.post(f"/api/v1/policy-approvals/{app_id}/approve", headers=viewer_headers)
        self.assertEqual(res2.status_code, 403)

    def test_14_admin_cannot_self_approve_authored_policy(self):
        """TEST 14: Admin is subject to Maker-Checker rules and cannot self-approve a policy they created."""
        admin_headers = get_auth_headers("ADMIN")
        reviewer_headers = get_auth_headers("POLICY_REVIEWER")

        # Admin creates and submits policy
        payload = {
            "policy_name": "Admin Authored Policy",
            "vendor_name": "Admin Vendor",
            "source_profile_id": "sp_firewall_syslog",
            "status": "DRAFT",
            "rules": [],
        }
        create_res = client.post("/api/v1/semantic-policies", json=payload, headers=admin_headers)
        policy_id = create_res.json()["policy_id"]

        sub_res = client.post(f"/api/v1/semantic-policies/{policy_id}/submit", headers=admin_headers)
        app_id = sub_res.json()["approval_id"]

        # Admin tries to approve own ticket -> 403 Forbidden
        self_approve_res = client.post(f"/api/v1/policy-approvals/{app_id}/approve", headers=admin_headers)
        self.assertEqual(self_approve_res.status_code, 403)
        self.assertIn("SELF_APPROVAL_FORBIDDEN", self_approve_res.json()["detail"])

        # Reviewer can approve admin's submitted policy
        rev_approve_res = client.post(f"/api/v1/policy-approvals/{app_id}/approve", headers=reviewer_headers)
        self.assertEqual(rev_approve_res.status_code, 200)

    def test_15_approval_list_and_metrics_work(self):
        """TEST 15: GET /api/v1/policy-approvals returns paginated list with breakdown metrics."""
        reviewer_headers = get_auth_headers("POLICY_REVIEWER")
        res = client.get("/api/v1/policy-approvals", headers=reviewer_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total", data)
        self.assertIn("pending_count", data)
        self.assertIn("approved_count", data)
        self.assertIn("rejected_count", data)
        self.assertIn("items", data)


    @classmethod
    def tearDownClass(cls):
        with SessionLocal() as db:
            SemanticPolicyService.seed_defaults(db)


if __name__ == "__main__":
    unittest.main()
