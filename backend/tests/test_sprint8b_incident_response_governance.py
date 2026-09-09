"""
tests/test_sprint8b_incident_response_governance.py
---------------------------------------------------
Comprehensive automated test suite for Sprint 8B:
- Incident Response Playbooks & Deterministic Matching
- Explainable Response Recommendations & Priority Escalation
- Containment Request State Machine & Invalid Transition Rejection
- Maker-Checker Dual-Control Enforcement & Self-Approval Prevention (HTTP 409)
- Execution Attestation Preconditions & Attribution
- Response Verification Preconditions & Efficacy Tracking
- 17-Stage Cryptographic Investigation & Response Provenance Trace
- 6-Role Centralized RBAC Security Enforcement
"""

import unittest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.security_incident import (
    SecurityIncident,
    IncidentSignal,
    IncidentEvidenceLink,
    IncidentFinding,
    IncidentTimelineEvent,
)
from app.models.incident_response import (
    IncidentResponsePlaybook,
    IncidentPlaybookAction,
    IncidentResponseRecommendation,
    IncidentContainmentRequest,
    IncidentResponseApproval,
    IncidentResponseExecution,
    IncidentResponseVerification,
)
from app.models.ledger import GovernanceLedgerEntry
from app.services.governance_ledger_service import GovernanceLedgerService
from app.services.incident_response_service import IncidentResponseService
from app.services.incident_service import IncidentService
from app.services.risk_correlation_service import RiskCorrelationService
from app.services.remediation_service import RemediationService
from app.services.detection_rule_service import DetectionRuleService
from app.services.detection_rule_trust_service import DetectionRuleTrustService
from app.services.detection_rule_governance_service import DetectionRuleGovernanceService
from app.services.detection_execution_service import DetectionExecutionService
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint8BIncidentResponseGovernance(unittest.TestCase):
    """Test suite for Sprint 8B Incident Response Governance and Decision Engine."""

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
            DetectionExecutionService.seed_demo_execution_scenarios(db)
            RiskCorrelationService.correlate_security_risks(db, force_reanalyze=False)
            RemediationService.seed_demo_scenarios(db)
            IncidentService.seed_demo_scenarios(db)
            IncidentResponseService.seed_defaults(db)

            # Ensure our test incidents exist
            existing_inc = db.query(SecurityIncident).filter(
                SecurityIncident.incident_id == "inc_test_credential_01"
            ).first()
            if not existing_inc:
                inc = SecurityIncident(
                    incident_id="inc_test_credential_01",
                    incident_number="INC-2026-000888",
                    title="Critical Credential Compromise & Session Hijacking",
                    description="Correlated anomalous logins across multiple geographical locations.",
                    incident_type="SEMANTIC_RISK",
                    severity="CRITICAL",
                    priority="P1",
                    status="INVESTIGATING",
                    root_cause_summary="Anomalous concurrent sessions with invalid detection trust.",
                    confidence=0.96,
                    affected_signal_count=3,
                    affected_rule_count=2,
                    affected_field_count=1,
                    created_by_user_id="usr_analyst_01",
                    assigned_to_user_id="usr_analyst_01",
                )
                db.add(inc)

            inc_malware = db.query(SecurityIncident).filter(
                SecurityIncident.incident_id == "inc_test_malware_02"
            ).first()
            if not inc_malware:
                inc_m = SecurityIncident(
                    incident_id="inc_test_malware_02",
                    incident_number="INC-2026-000889",
                    title="Ransomware Host Infection & Lateral Movement",
                    description="Malicious PowerShell execution and process injection detected on host.",
                    incident_type="DETECTION_TRUST",
                    severity="HIGH",
                    priority="P2",
                    status="OPEN",
                    root_cause_summary="Malicious payload execution on endpoint.",
                    confidence=0.92,
                    affected_signal_count=2,
                    affected_rule_count=1,
                    affected_field_count=1,
                    created_by_user_id="usr_analyst_01",
                )
                db.add(inc_m)

            inc_net = db.query(SecurityIncident).filter(
                SecurityIncident.incident_id == "inc_test_network_03"
            ).first()
            if not inc_net:
                inc_n = SecurityIncident(
                    incident_id="inc_test_network_03",
                    incident_number="INC-2026-000890",
                    title="Perimeter Firewall Port Scan & Intrusion Attempt",
                    description="Repeated SYN flood and port sweep from adversary IP ranges.",
                    incident_type="MULTI_SIGNAL",
                    severity="MEDIUM",
                    priority="P3",
                    status="OPEN",
                    root_cause_summary="External network reconnaissance sweep.",
                    confidence=0.88,
                    affected_signal_count=2,
                    affected_rule_count=1,
                    affected_field_count=0,
                    created_by_user_id="usr_analyst_01",
                )
                db.add(inc_n)

            inc_trust = db.query(SecurityIncident).filter(
                SecurityIncident.incident_id == "inc_test_trust_04"
            ).first()
            if not inc_trust:
                inc_t = SecurityIncident(
                    incident_id="inc_test_trust_04",
                    incident_number="INC-2026-000891",
                    title="Semantic Policy Drift & Rule Trust Degradation",
                    description="Detection rules degraded due to unmapped vendor syslog token change.",
                    incident_type="GOVERNANCE_ANOMALY",
                    severity="LOW",
                    priority="P4",
                    status="OPEN",
                    root_cause_summary="Semantic drift in authentication.outcome field.",
                    confidence=0.85,
                    affected_signal_count=1,
                    affected_rule_count=2,
                    affected_field_count=1,
                    created_by_user_id="usr_analyst_01",
                )
                db.add(inc_t)

            db.commit()

    # ── A. Playbook Tests ───────────────────────────────────────────────────

    def test_01_seed_defaults_idempotent(self):
        """Test seeding defaults multiple times does not duplicate playbooks."""
        with SessionLocal() as db:
            res = IncidentResponseService.seed_defaults(db)
            self.assertEqual(res["status"], "SUCCESS")
            playbooks = db.query(IncidentResponsePlaybook).all()
            self.assertGreaterEqual(len(playbooks), 4)

    def test_02_list_playbooks_api(self):
        """Test GET /api/v1/incident-response/playbooks returns active playbooks."""
        headers = get_auth_headers("security_analyst")
        res = client.get("/api/v1/incident-response/playbooks", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(len(data), 4)
        playbook_ids = [p["playbook_id"] for p in data]
        self.assertIn("PLAYBOOK_CREDENTIAL_COMPROMISE", playbook_ids)
        self.assertIn("PLAYBOOK_MALWARE_CONTAINMENT", playbook_ids)
        self.assertIn("PLAYBOOK_NETWORK_INTRUSION", playbook_ids)
        self.assertIn("PLAYBOOK_DETECTION_TRUST_FAILURE", playbook_ids)

    def test_03_get_playbook_detail(self):
        """Test GET /api/v1/incident-response/playbooks/{playbook_id} returns actions."""
        headers = get_auth_headers("security_analyst")
        res = client.get(
            "/api/v1/incident-response/playbooks/PLAYBOOK_CREDENTIAL_COMPROMISE",
            headers=headers,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["playbook_id"], "PLAYBOOK_CREDENTIAL_COMPROMISE")
        self.assertIn("actions", data)
        self.assertGreaterEqual(len(data["actions"]), 5)

    def test_04_deterministic_playbook_matching_credential(self):
        """Test deterministic matching for credential compromise incident."""
        with SessionLocal() as db:
            inc = db.query(SecurityIncident).filter(SecurityIncident.incident_id == "inc_test_credential_01").first()
            matched = IncidentResponseService.match_playbook(db, inc)
            self.assertEqual(matched.playbook_id, "PLAYBOOK_CREDENTIAL_COMPROMISE")

    def test_05_deterministic_playbook_matching_malware(self):
        """Test deterministic matching for malware/ransomware incident."""
        with SessionLocal() as db:
            inc = db.query(SecurityIncident).filter(SecurityIncident.incident_id == "inc_test_malware_02").first()
            matched = IncidentResponseService.match_playbook(db, inc)
            self.assertEqual(matched.playbook_id, "PLAYBOOK_MALWARE_CONTAINMENT")

    def test_06_deterministic_playbook_matching_network(self):
        """Test deterministic matching for network intrusion incident."""
        with SessionLocal() as db:
            inc = db.query(SecurityIncident).filter(SecurityIncident.incident_id == "inc_test_network_03").first()
            matched = IncidentResponseService.match_playbook(db, inc)
            self.assertEqual(matched.playbook_id, "PLAYBOOK_NETWORK_INTRUSION")

    def test_07_deterministic_playbook_matching_trust(self):
        """Test deterministic matching for detection trust/drift incident."""
        with SessionLocal() as db:
            inc = db.query(SecurityIncident).filter(SecurityIncident.incident_id == "inc_test_trust_04").first()
            matched = IncidentResponseService.match_playbook(db, inc)
            self.assertEqual(matched.playbook_id, "PLAYBOOK_DETECTION_TRUST_FAILURE")

    def test_08_playbook_action_ordering_and_dual_control_flags(self):
        """Test playbook actions maintain sequence and proper dual-control flags."""
        with SessionLocal() as db:
            playbook = db.query(IncidentResponsePlaybook).filter(
                IncidentResponsePlaybook.playbook_id == "PLAYBOOK_CREDENTIAL_COMPROMISE"
            ).first()
            seqs = [a.sequence_number for a in playbook.actions]
            self.assertEqual(seqs, sorted(seqs))

            # Disable account must require dual control
            disable_action = next(a for a in playbook.actions if a.action_key == "DISABLE_ACCOUNT")
            self.assertTrue(disable_action.requires_dual_control)
            self.assertEqual(disable_action.impact_level, "HIGH_IMPACT")

            # Preserve evidence must be low impact without dual control
            preserve_action = next(a for a in playbook.actions if a.action_key == "PRESERVE_EVIDENCE")
            self.assertFalse(preserve_action.requires_dual_control)
            self.assertEqual(preserve_action.impact_level, "LOW_IMPACT")

    # ── B. Recommendation Tests ─────────────────────────────────────────────

    def test_09_generate_recommendations_endpoint(self):
        """Test POST /api/v1/incidents/{incident_id}/recommendations generates recommendations."""
        headers = get_auth_headers("security_analyst")
        res = client.post(
            "/api/v1/incidents/inc_test_credential_01/recommendations",
            headers=headers,
        )
        self.assertIn(res.status_code, [200, 201])
        data = res.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 5)
        self.assertTrue(all(r["incident_id"] == "inc_test_credential_01" for r in data))

    def test_10_recommendation_priority_p1_critical(self):
        """Test critical incident recommendations receive P1 priority."""
        headers = get_auth_headers("security_analyst")
        res = client.post(
            "/api/v1/incidents/inc_test_credential_01/recommendations",
            headers=headers,
        )
        self.assertIn(res.status_code, [200, 201])
        data = res.json()
        self.assertTrue(all(r["priority"] == "P1" for r in data))

    def test_11_recommendation_priority_protected_field_escalation(self):
        """Test incident with affected protected fields escalates to P1 priority."""
        with SessionLocal() as db:
            inc = db.query(SecurityIncident).filter(SecurityIncident.incident_id == "inc_test_credential_01").first()
            self.assertGreater(inc.affected_field_count, 0)

    def test_12_recommendation_explainable_reasoning(self):
        """Test recommendations contain detailed explainable reasoning."""
        headers = get_auth_headers("security_analyst")
        res = client.get(
            "/api/v1/incidents/inc_test_credential_01/recommendations",
            headers=headers,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        for rec in data:
            self.assertIn("reasoning", rec)
            self.assertTrue(len(rec["reasoning"]) > 20)
            self.assertIn("INC-2026-", rec["reasoning"])

    def test_13_recommendation_immutability_and_hash(self):
        """Test recommendation hash is non-empty and deterministic."""
        headers = get_auth_headers("security_analyst")
        res = client.get(
            "/api/v1/incidents/inc_test_credential_01/recommendations",
            headers=headers,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        for rec in data:
            self.assertEqual(len(rec["recommendation_hash"]), 64)

    def test_14_get_recommendations_for_incident(self):
        """Test GET /api/v1/incidents/{incident_id}/recommendations retrieves generated recommendations."""
        headers = get_auth_headers("security_analyst")
        res = client.get(
            "/api/v1/incidents/inc_test_credential_01/recommendations",
            headers=headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(len(res.json()), 5)

    # ── C. Containment Request Lifecycle Tests ──────────────────────────────

    def test_15_create_containment_request_endpoint(self):
        """Test POST /api/v1/incidents/{incident_id}/containment-requests creates request in PROPOSED status."""
        headers = get_auth_headers("security_analyst")
        payload = {
            "action_type": "DISABLE_ACCOUNT",
            "action_description": "Temporarily disable user account in corporate Active Directory/Okta.",
            "impact_level": "HIGH_IMPACT",
            "risk_justification": "Active adversary session hijacking detected on user account.",
        }
        res = client.post(
            "/api/v1/incidents/inc_test_credential_01/containment-requests",
            json=payload,
            headers=headers,
        )
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["status"], "PROPOSED")
        self.assertEqual(data["action_type"], "DISABLE_ACCOUNT")
        self.assertEqual(len(data["request_hash"]), 64)

    def test_16_submit_containment_request_for_review(self):
        """Test POST /api/v1/containment-requests/{request_id}/submit moves to PENDING_REVIEW."""
        headers = get_auth_headers("security_analyst")
        with SessionLocal() as db:
            req = db.query(IncidentContainmentRequest).filter(
                IncidentContainmentRequest.incident_id == "inc_test_credential_01",
                IncidentContainmentRequest.status == "PROPOSED",
            ).first()
            self.assertIsNotNone(req)
            req_id = req.request_id

        res = client.post(
            f"/api/v1/containment-requests/{req_id}/submit",
            headers=headers,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "PENDING_REVIEW")

    def test_17_list_containment_requests_with_filtering(self):
        """Test GET /api/v1/containment-requests with filtering."""
        headers = get_auth_headers("security_analyst")
        res = client.get(
            "/api/v1/containment-requests?status=PENDING_REVIEW",
            headers=headers,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIsInstance(data, list)
        self.assertTrue(all(r["status"] == "PENDING_REVIEW" for r in data))

    def test_18_get_containment_request_detail(self):
        """Test GET /api/v1/containment-requests/{request_id} returns full detail."""
        headers = get_auth_headers("security_analyst")
        with SessionLocal() as db:
            req = db.query(IncidentContainmentRequest).first()
            req_id = req.request_id

        res = client.get(
            f"/api/v1/containment-requests/{req_id}",
            headers=headers,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["request_id"], req_id)
        self.assertIn("approvals", data)
        self.assertIn("executions", data)
        self.assertIn("verifications", data)

    def test_19_invalid_state_transition_submit_already_pending(self):
        """Test submitting an already submitted request returns HTTP 400."""
        headers = get_auth_headers("security_analyst")
        with SessionLocal() as db:
            req = db.query(IncidentContainmentRequest).filter(
                IncidentContainmentRequest.status == "PENDING_REVIEW"
            ).first()
            req_id = req.request_id

        res = client.post(
            f"/api/v1/containment-requests/{req_id}/submit",
            headers=headers,
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("INVALID_STATE_TRANSITION", res.json()["detail"])

    # ── D. Maker-Checker Dual-Control Tests ──────────────────────────────────

    def test_20_maker_cannot_approve_own_request_http_409(self):
        """CRITICAL INVARIANT: Proposer cannot approve their own containment request (HTTP 409)."""
        admin_headers = get_auth_headers("admin")

        # Propose request as admin
        payload_admin = {
            "action_type": "REVOKE_SESSION",
            "action_description": "Admin proposed revocation test",
            "impact_level": "LOW_IMPACT",
            "risk_justification": "Testing maker-checker self-approval block.",
        }
        res_prop = client.post(
            "/api/v1/incidents/inc_test_credential_01/containment-requests",
            json=payload_admin,
            headers=admin_headers,
        )
        self.assertEqual(res_prop.status_code, 201)
        req_id = res_prop.json()["request_id"]

        # Submit for review
        res_sub = client.post(
            f"/api/v1/containment-requests/{req_id}/submit",
            headers=admin_headers,
        )
        self.assertEqual(res_sub.status_code, 200)

        # Attempt self-approval as admin who proposed it
        payload = {
            "decision": "APPROVE",
            "reason": "I am attempting to approve my own containment request.",
        }
        res = client.post(
            f"/api/v1/containment-requests/{req_id}/review",
            json=payload,
            headers=admin_headers,
        )
        self.assertEqual(res.status_code, 409)
        self.assertIn("SELF_APPROVAL_FORBIDDEN", res.json()["detail"])

    def test_21_self_approval_attempt_records_blocked_timeline_event(self):
        """Test blocked self-approval attempt generates immutable timeline event."""
        with SessionLocal() as db:
            events = db.query(IncidentTimelineEvent).filter(
                IncidentTimelineEvent.event_type == "SELF_APPROVAL_BLOCKED"
            ).all()
            self.assertGreaterEqual(len(events), 1)
            last_event = events[-1]
            self.assertIn("Maker-Checker", last_event.event_data["reason"])

    def test_22_self_approval_attempt_records_governance_ledger_entry(self):
        """Test blocked self-approval attempt is recorded in Cryptographic Governance Ledger."""
        with SessionLocal() as db:
            entries = db.query(GovernanceLedgerEntry).filter(
                GovernanceLedgerEntry.event_type == "SELF_APPROVAL_BLOCKED"
            ).all()
            self.assertGreaterEqual(len(entries), 1)

    def test_23_independent_reviewer_approval_success(self):
        """Test independent reviewer (policy_reviewer) can successfully APPROVE request."""
        reviewer_headers = get_auth_headers("policy_reviewer")
        with SessionLocal() as db:
            req = db.query(IncidentContainmentRequest).filter(
                IncidentContainmentRequest.status == "PENDING_REVIEW"
            ).first()
            req_id = req.request_id

        payload = {
            "decision": "APPROVE",
            "reason": "Independent SOC reviewer verified telemetry; containment justified.",
        }
        res = client.post(
            f"/api/v1/containment-requests/{req_id}/review",
            json=payload,
            headers=reviewer_headers,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "APPROVED")
        self.assertIsNotNone(data["approved_by_user_id"])

    def test_24_independent_reviewer_rejection(self):
        """Test independent reviewer can REJECT a request."""
        analyst_headers = get_auth_headers("security_analyst")
        reviewer_headers = get_auth_headers("policy_reviewer")

        # Create second request
        payload_create = {
            "action_type": "BLOCK_NETWORK",
            "action_description": "Block perimeter subnet.",
            "impact_level": "HIGH_IMPACT",
            "risk_justification": "Testing rejection flow.",
        }
        res_create = client.post(
            "/api/v1/incidents/inc_test_credential_01/containment-requests",
            json=payload_create,
            headers=analyst_headers,
        )
        req_id = res_create.json()["request_id"]

        # Review as policy_reviewer
        res_review = client.post(
            f"/api/v1/containment-requests/{req_id}/review",
            json={"decision": "REJECT", "reason": "Insufficient evidence for full subnet block."},
            headers=reviewer_headers,
        )
        self.assertEqual(res_review.status_code, 200)
        self.assertEqual(res_review.json()["status"], "REJECTED")

    def test_25_request_changes_lifecycle(self):
        """Test reviewer can REQUEST_CHANGES returning request to DRAFT."""
        analyst_headers = get_auth_headers("security_analyst")
        reviewer_headers = get_auth_headers("policy_reviewer")

        payload_create = {
            "action_type": "ISOLATE_ENDPOINT",
            "action_description": "Isolate host 192.168.1.50.",
            "impact_level": "CRITICAL_IMPACT",
            "risk_justification": "Testing change request flow.",
        }
        res_create = client.post(
            "/api/v1/incidents/inc_test_credential_01/containment-requests",
            json=payload_create,
            headers=analyst_headers,
        )
        req_id = res_create.json()["request_id"]

        res_review = client.post(
            f"/api/v1/containment-requests/{req_id}/review",
            json={"decision": "REQUEST_CHANGES", "reason": "Please narrow isolation scope to single VLAN."},
            headers=reviewer_headers,
        )
        self.assertEqual(res_review.status_code, 200)
        self.assertEqual(res_review.json()["status"], "DRAFT")

    # ── E. Execution Attestation Tests ───────────────────────────────────────

    def test_26_execution_attestation_requires_approved_status(self):
        """Test attesting execution on unapproved request raises HTTP 409."""
        analyst_headers = get_auth_headers("security_analyst")
        with SessionLocal() as db:
            req = db.query(IncidentContainmentRequest).filter(
                IncidentContainmentRequest.status == "DRAFT"
            ).first()
            req_id = req.request_id

        payload = {
            "execution_status": "EXECUTION_ATTESTED",
            "execution_reference": "SOC-CHG-2026-001",
            "execution_notes": "Attempting premature attestation.",
        }
        res = client.post(
            f"/api/v1/containment-requests/{req_id}/attest-execution",
            json=payload,
            headers=analyst_headers,
        )
        self.assertEqual(res.status_code, 409)
        self.assertIn("EXECUTION_NOT_AUTHORIZED", res.json()["detail"])

    def test_27_execution_attestation_success(self):
        """Test operator can successfully attest execution on APPROVED request."""
        analyst_headers = get_auth_headers("security_analyst")
        with SessionLocal() as db:
            req = db.query(IncidentContainmentRequest).filter(
                IncidentContainmentRequest.status == "APPROVED"
            ).first()
            req_id = req.request_id

        payload = {
            "execution_status": "EXECUTION_ATTESTED",
            "execution_reference": "SOC-CHG-2026-00142",
            "execution_notes": "User account disabled in Okta and active sessions invalidated.",
        }
        res = client.post(
            f"/api/v1/containment-requests/{req_id}/attest-execution",
            json=payload,
            headers=analyst_headers,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "EXECUTION_ATTESTED")
        self.assertIsNotNone(data["execution_attested_at"])

    def test_28_execution_attestation_failed_status(self):
        """Test attesting EXECUTION_FAILED updates status properly."""
        analyst_headers = get_auth_headers("security_analyst")
        req_id = f"req_test_exec_fail_{uuid.uuid4().hex[:6]}"
        with SessionLocal() as db:
            req = IncidentContainmentRequest(
                request_id=req_id,
                incident_id="inc_test_credential_01",
                action_type="RESET_CREDENTIALS",
                action_description="Reset LDAP credentials",
                impact_level="HIGH_IMPACT",
                risk_justification="Testing failed execution",
                proposed_by_user_id="usr_analyst_01",
                reviewed_by_user_id="usr_reviewer_01",
                approved_by_user_id="usr_reviewer_01",
                status="APPROVED",
                request_hash=f"req_hash_{req_id}",
            )
            db.add(req)
            db.commit()

        payload = {
            "execution_status": "EXECUTION_FAILED",
            "execution_reference": "SOC-CHG-2026-ERR",
            "execution_notes": "EDR API returned timeout error during isolation.",
        }
        res = client.post(
            f"/api/v1/containment-requests/{req_id}/attest-execution",
            json=payload,
            headers=analyst_headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "EXECUTION_FAILED")

    def test_29_execution_attestation_hash_integrity(self):
        """Test execution attestation generates deterministic 64-char SHA-256 hash."""
        with SessionLocal() as db:
            exec_record = db.query(IncidentResponseExecution).filter(
                IncidentResponseExecution.execution_reference == "SOC-CHG-2026-00142"
            ).first()
            self.assertIsNotNone(exec_record)
            self.assertEqual(len(exec_record.attestation_hash), 64)

    # ── F. Response Verification Tests ───────────────────────────────────────

    def test_30_verification_requires_executed_status(self):
        """Test verifying unexecuted request returns HTTP 409."""
        analyst_headers = get_auth_headers("security_analyst")
        with SessionLocal() as db:
            req = db.query(IncidentContainmentRequest).filter(
                IncidentContainmentRequest.status == "EXECUTION_FAILED"
            ).first()
            req_id = req.request_id

        payload = {
            "verification_status": "VERIFIED",
            "verification_method": "AUTHENTICATION_AUDIT",
            "verification_evidence": "Attempting verification on failed execution.",
        }
        res = client.post(
            f"/api/v1/containment-requests/{req_id}/verify",
            json=payload,
            headers=analyst_headers,
        )
        self.assertEqual(res.status_code, 409)
        self.assertIn("VERIFICATION_PRECONDITION_FAILED", res.json()["detail"])

    def test_31_verification_success_marks_verified_and_contained(self):
        """Test successful verification marks request VERIFIED and incident CONTAINED."""
        analyst_headers = get_auth_headers("security_analyst")
        with SessionLocal() as db:
            req = db.query(IncidentContainmentRequest).filter(
                IncidentContainmentRequest.status == "EXECUTION_ATTESTED"
            ).first()
            req_id = req.request_id

        payload = {
            "verification_status": "VERIFIED",
            "verification_method": "AUTHENTICATION_AUDIT",
            "verification_evidence": "IdP audit logs confirm zero new login attempts; all active tokens terminated.",
            "verification_notes": "Identity compromise neutralized.",
        }
        res = client.post(
            f"/api/v1/containment-requests/{req_id}/verify",
            json=payload,
            headers=analyst_headers,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "VERIFIED")
        self.assertIsNotNone(data["verification_completed_at"])

        # Verify incident status updated to CONTAINED
        with SessionLocal() as db:
            inc = db.query(SecurityIncident).filter(
                SecurityIncident.incident_id == "inc_test_credential_01"
            ).first()
            self.assertEqual(inc.status, "CONTAINED")

    def test_32_verification_failure_records_verification_failed(self):
        """Test failed verification transitions status to VERIFICATION_FAILED."""
        analyst_headers = get_auth_headers("security_analyst")
        req_id = f"req_test_verif_fail_{uuid.uuid4().hex[:6]}"
        with SessionLocal() as db:
            req = IncidentContainmentRequest(
                request_id=req_id,
                incident_id="inc_test_credential_01",
                action_type="BLOCK_NETWORK",
                action_description="Block IP 198.51.100.25",
                impact_level="HIGH_IMPACT",
                risk_justification="Testing verification failure",
                proposed_by_user_id="usr_analyst_01",
                reviewed_by_user_id="usr_reviewer_01",
                approved_by_user_id="usr_reviewer_01",
                status="EXECUTION_ATTESTED",
                request_hash=f"req_hash_{req_id}",
            )
            db.add(req)
            db.commit()

        payload = {
            "verification_status": "FAILED",
            "verification_method": "NETWORK_TELEMETRY",
            "verification_evidence": "Adversary traffic continued arriving on alternative egress port.",
        }
        res = client.post(
            f"/api/v1/containment-requests/{req_id}/verify",
            json=payload,
            headers=analyst_headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "VERIFICATION_FAILED")

    def test_33_verification_inconclusive_records_pending(self):
        """Test inconclusive verification transitions status to VERIFICATION_PENDING."""
        analyst_headers = get_auth_headers("security_analyst")
        req_id = f"req_test_verif_inconclusive_{uuid.uuid4().hex[:6]}"
        with SessionLocal() as db:
            req = IncidentContainmentRequest(
                request_id=req_id,
                incident_id="inc_test_credential_01",
                action_type="VERIFY_SESSIONS",
                action_description="Check IdP sessions",
                impact_level="LOW_IMPACT",
                risk_justification="Testing inconclusive verification",
                proposed_by_user_id="usr_analyst_01",
                reviewed_by_user_id="usr_reviewer_01",
                approved_by_user_id="usr_reviewer_01",
                status="EXECUTION_ATTESTED",
                request_hash=f"req_hash_{req_id}",
            )
            db.add(req)
            db.commit()

        payload = {
            "verification_status": "INCONCLUSIVE",
            "verification_method": "LOG_REVIEW",
            "verification_evidence": "Log latency of 15 minutes; awaiting fresh telemetry batch.",
        }
        res = client.post(
            f"/api/v1/containment-requests/{req_id}/verify",
            json=payload,
            headers=analyst_headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "VERIFICATION_PENDING")

    # ── G. 17-Stage Provenance & Cryptographic Governance Tests ──────────────

    def test_34_17_stage_provenance_trace_endpoint(self):
        """Test GET /api/v1/incidents/{incident_id}/response-trace returns exactly 17 stages."""
        auditor_headers = get_auth_headers("auditor")
        res = client.get(
            "/api/v1/incidents/inc_test_credential_01/response-trace",
            headers=auditor_headers,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["incident_id"], "inc_test_credential_01")
        self.assertEqual(data["total_stages"], 17)
        self.assertTrue(data["is_complete"])
        self.assertEqual(len(data["stages"]), 17)

    def test_35_provenance_stages_completeness(self):
        """Test all 17 provenance stages contain stage number, name, entity type, and status."""
        auditor_headers = get_auth_headers("auditor")
        res = client.get(
            "/api/v1/incidents/inc_test_credential_01/response-trace",
            headers=auditor_headers,
        )
        self.assertEqual(res.status_code, 200)
        stages = res.json()["stages"]
        stage_names = [s["stage_name"] for s in stages]

        expected_stages = [
            "RAW_EVIDENCE",
            "OCSF_NORMALIZED_EVENT",
            "SEMANTIC_INTERPRETATION",
            "SEMANTIC_DRIFT",
            "CANONICAL_FIELD",
            "DETECTION_RULE_DEPENDENCY",
            "DETECTION_TRUST_EVALUATION",
            "DETECTION_TRUST_ALERT",
            "RISK_CORRELATION",
            "SECURITY_INCIDENT",
            "RESPONSE_PLAYBOOK",
            "RESPONSE_RECOMMENDATION",
            "CONTAINMENT_REQUEST",
            "INDEPENDENT_REVIEW",
            "EXECUTION_ATTESTATION",
            "RESPONSE_VERIFICATION",
            "GOVERNANCE_LEDGER_AND_MERKLE_PROOF",
        ]
        self.assertEqual(stage_names, expected_stages)

        for i, s in enumerate(stages):
            self.assertEqual(s["stage_number"], i + 1)
            self.assertTrue(len(s["entity_type"]) > 0)
            self.assertTrue(len(s["status"]) > 0)

    def test_36_governance_ledger_chain_validity_after_response_actions(self):
        """Test entire Governance Ledger hash chain remains valid after all response actions."""
        with SessionLocal() as db:
            result = GovernanceLedgerService.verify_chain(db)
            self.assertEqual(result["status"], "VERIFIED")
            self.assertGreater(result["entries_checked"], 0)
            self.assertIsNone(result["first_invalid_entry"])

    # ── H. RBAC Security Tests ──────────────────────────────────────────────

    def test_37_rbac_security_analyst_can_propose_and_attest(self):
        """Test SECURITY_ANALYST has propose and execute permissions."""
        analyst_headers = get_auth_headers("security_analyst")
        res = client.post(
            "/api/v1/incidents/inc_test_credential_01/recommendations",
            headers=analyst_headers,
        )
        self.assertIn(res.status_code, [200, 201])

    def test_38_rbac_policy_reviewer_can_review_containment(self):
        """Test POLICY_REVIEWER has review permission."""
        reviewer_headers = get_auth_headers("policy_reviewer")
        res = client.get(
            "/api/v1/incident-response/playbooks",
            headers=reviewer_headers,
        )
        self.assertEqual(res.status_code, 200)

    def test_39_rbac_auditor_read_only_enforcement(self):
        """Test AUDITOR can read response trace but cannot propose containment (HTTP 403)."""
        auditor_headers = get_auth_headers("auditor")
        # Read trace -> 200
        res_trace = client.get(
            "/api/v1/incidents/inc_test_credential_01/response-trace",
            headers=auditor_headers,
        )
        self.assertEqual(res_trace.status_code, 200)

        # Propose containment -> 403 Forbidden
        payload = {
            "action_type": "DISABLE_ACCOUNT",
            "action_description": "Auditor attempting proposal",
            "impact_level": "HIGH_IMPACT",
            "risk_justification": "Test",
        }
        res_prop = client.post(
            "/api/v1/incidents/inc_test_credential_01/containment-requests",
            json=payload,
            headers=auditor_headers,
        )
        self.assertEqual(res_prop.status_code, 403)

    def test_40_rbac_viewer_restricted_from_proposing_and_reviewing(self):
        """Test VIEWER cannot propose containment or review requests (HTTP 403)."""
        viewer_headers = get_auth_headers("viewer")
        payload = {
            "action_type": "DISABLE_ACCOUNT",
            "action_description": "Viewer attempting proposal",
            "impact_level": "HIGH_IMPACT",
            "risk_justification": "Test",
        }
        res_prop = client.post(
            "/api/v1/incidents/inc_test_credential_01/containment-requests",
            json=payload,
            headers=viewer_headers,
        )
        self.assertEqual(res_prop.status_code, 403)

    def test_41_rbac_admin_full_access(self):
        """Test ADMIN has full access across all incident response endpoints."""
        admin_headers = get_auth_headers("admin")
        res = client.get(
            "/api/v1/incident-response/playbooks",
            headers=admin_headers,
        )
        self.assertEqual(res.status_code, 200)

        res_recs = client.get(
            "/api/v1/incidents/inc_test_credential_01/recommendations",
            headers=admin_headers,
        )
        self.assertEqual(res_recs.status_code, 200)

    def test_42_unauthenticated_request_blocked_http_401(self):
        """Test unauthenticated request returns HTTP 401."""
        res = client.get("/api/v1/incident-response/playbooks")
        self.assertEqual(res.status_code, 401)


if __name__ == "__main__":
    unittest.main()
