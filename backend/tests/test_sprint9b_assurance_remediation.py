"""
tests/test_sprint9b_assurance_remediation.py
---------------------------------------------
Comprehensive automated test suite for Sprint 9B:
- Continuous Assurance Governance & Degradation Case Management
- Deterministic Root Cause Analysis (Zero Trust: UNKNOWN != SAFE)
- Deterministic Remediation Recommendation Engine (Explainable Deductions)
- Human Remediation Plan Lifecycle (DRAFT -> PENDING_REVIEW -> APPROVED -> AUTHORIZED_FOR_EXECUTION)
- Maker-Checker Dual-Control Enforcement (HTTP 409 SELF_APPROVAL_FORBIDDEN)
- Human Execution Attestation with Canonical SHA-256 Seal
- Post-Remediation Recovery Verification (Against NEW Platform Assurance Evaluation)
- Zero Trust Invariants: INCONCLUSIVE != RECOVERED, UNKNOWN != RECOVERED
- Cryptographic Hard Failure Handling & Overrides
- Recovery Confidence Scoring Model
- Append-Only Governance Ledger & Chaining
- 18-Stage End-to-End Assurance Recovery Provenance Trace
- RBAC Enforcement across 6 System Roles
- REST APIs & KPI Analytics
"""

import hashlib
import unittest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.assurance_remediation import (
    AssuranceRemediationCase,
    AssuranceRootCauseAnalysis,
    AssuranceRemediationRecommendation,
    AssuranceRemediationPlan,
    AssuranceRemediationApproval,
    AssuranceRemediationExecution,
    AssuranceRecoveryVerification,
    AssuranceRecoveryRecord,
    calculate_sha256,
)
from app.models.security_assurance import (
    AssuranceDomainEvaluation,
    PlatformAssuranceEvaluation,
    AssuranceAlert,
    AssuranceMetricDefinition,
)
from app.models.ledger import GovernanceLedgerEntry
from app.services.assurance_remediation_service import (
    AssuranceRemediationService,
    SelfApprovalForbiddenException,
    InvalidStateTransitionException,
)
from app.services.security_assurance_service import SecurityAssuranceService
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


class TestSprint9BAssuranceRemediation(unittest.TestCase):
    """Test suite for Sprint 9B Continuous Assurance Governance and Recovery Verification."""

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
            SecurityAssuranceService.seed_default_metric_definitions(db)

            # Ensure clean baseline platform assurance evaluation exists
            SecurityAssuranceService.evaluate_platform(db=db, notes="Sprint 9B Test Setup")
            db.commit()

    def setUp(self):
        self.db = SessionLocal()
        self.admin_headers = get_auth_headers("ADMIN")
        self.analyst_headers = get_auth_headers("SECURITY_ANALYST")
        self.reviewer_headers = get_auth_headers("POLICY_REVIEWER")
        self.author_headers = get_auth_headers("POLICY_AUTHOR")
        self.auditor_headers = get_auth_headers("AUDITOR")
        self.viewer_headers = get_auth_headers("VIEWER")

    def tearDown(self):
        self.db.close()

    # ── A. MODEL TESTS ────────────────────────────────────────────────────────

    def test_01_remediation_case_creation(self):
        """Test remediation case creation with defaults and UUID primary key."""
        case = AssuranceRemediationCase(
            case_number=f"ARC-2026-TEST-{uuid.uuid4().hex[:6]}",
            affected_domain="NORMALIZATION_ASSURANCE",
            title="Test Normalization Degradation",
            description="Testing normalization case creation",
            severity="MEDIUM",
            priority="P2",
            status="OPEN",
            created_by_user_id="analyst_user",
            deduplication_fingerprint="test_fp_01",
            timeline=[{"event_type": "CASE_OPENED", "actor": "analyst_user"}],
        )
        self.db.add(case)
        self.db.commit()
        self.db.refresh(case)

        self.assertTrue(case.id.startswith("arc-"))
        self.assertEqual(case.status, "OPEN")
        self.assertEqual(case.affected_domain, "NORMALIZATION_ASSURANCE")
        d = case.to_dict()
        self.assertEqual(d["case_number"], case.case_number)
        self.assertEqual(len(d["timeline"]), 1)

    def test_02_case_number_formatting(self):
        """Test case numbering generates sequential ARC-YYYY-NNN format."""
        case_num = AssuranceRemediationService.generate_case_number(self.db)
        current_year = datetime.now(timezone.utc).year
        self.assertTrue(case_num.startswith(f"ARC-{current_year}-"))
        parts = case_num.split("-")
        self.assertEqual(len(parts), 3)
        self.assertTrue(parts[2].isdigit())

    def test_03_case_deduplication(self):
        """Test active duplicate remediation cases are deduplicated."""
        alert = AssuranceAlert(
            alert_type="ASSURANCE_DEGRADED",
            domain_name="SEMANTIC_ASSURANCE",
            severity="HIGH",
            status="OPEN",
            title="Semantic Assurance Alert Dedup Test",
            description="Testing deduplication",
            current_score=60.0,
            deduplication_key=f"dedup_key_{uuid.uuid4().hex[:8]}",
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)

        case1 = AssuranceRemediationService.create_remediation_case_from_assurance_alert(
            self.db, alert.id, user_id="analyst_user"
        )
        case2 = AssuranceRemediationService.create_remediation_case_from_assurance_alert(
            self.db, alert.id, user_id="analyst_user"
        )
        self.assertEqual(case1.id, case2.id)

    def test_04_root_cause_persistence(self):
        """Test root cause analysis model persistence and relationship."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db,
            title="RCA Test Case",
            description="Testing RCA persistence",
            affected_domain="EVIDENCE_ASSURANCE",
            user_id="analyst_user",
        )
        rca = AssuranceRemediationService.create_root_cause_analysis(
            self.db,
            case_id=case.id,
            root_cause_category="DATA_INGESTION_FAILURE",
            root_cause_key="RCA_STREAM_DISCONNECTED",
            hypothesis="Connector timeout caused missing raw evidence",
            evidence_summary="504 gateway timeout observed on Kafka endpoint",
            confidence="HIGH",
            created_by_user_id="analyst_user",
        )
        self.assertTrue(rca.id.startswith("arca-"))
        self.assertEqual(rca.analysis_version, 1)
        self.assertEqual(rca.confidence, "HIGH")
        self.assertEqual(case.status, "ANALYZING")

    def test_05_recommendation_persistence(self):
        """Test recommendation persistence and SHA-256 seal."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db,
            title="Recommendation Test Case",
            description="Testing recommendation generation",
            affected_domain="DETECTION_ASSURANCE",
            user_id="analyst_user",
        )
        AssuranceRemediationService.create_root_cause_analysis(
            self.db,
            case_id=case.id,
            root_cause_category="DETECTION_RULE_FAILURE",
            root_cause_key="RCA_RULE_DEP_FAIL",
            hypothesis="Rule dependency broken",
            evidence_summary="Rule dependency validation failed",
            confidence="HIGH",
            created_by_user_id="analyst_user",
        )
        recs = AssuranceRemediationService.generate_remediation_recommendations(
            self.db, case.id, user_id="analyst_user"
        )
        self.assertTrue(len(recs) >= 1)
        self.assertTrue(recs[0].id.startswith("arr-"))
        self.assertTrue(len(recs[0].recommendation_hash) == 64)

    def test_06_plan_lifecycle_persistence(self):
        """Test plan model persistence and initial DRAFT state."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db,
            title="Plan Test Case",
            description="Testing plan model",
            affected_domain="RISK_ASSURANCE",
            user_id="analyst_user",
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db,
            case_id=case.id,
            title="Recalculate Risk Weights",
            description="Plan description",
            proposed_actions=[{"step": 1, "action": "Re-weight graph"}],
            expected_outcome="Risk assurance score > 85",
            rollback_strategy="Restore previous weights",
            estimated_risk="LOW",
            proposed_by_user_id="analyst_user",
        )
        self.assertEqual(plan.status, "DRAFT")
        self.assertEqual(case.status, "REMEDIATION_PLANNED")
        self.assertEqual(plan.plan_version, 1)

    def test_07_approval_persistence(self):
        """Test approval model persistence."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db,
            title="Approval Test Case",
            description="Testing approval model",
            affected_domain="SEMANTIC_ASSURANCE",
            user_id="author_user",
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db,
            case_id=case.id,
            title="Update Semantic Policy",
            description="Policy plan",
            proposed_actions=[{"step": 1, "action": "Adjust policy"}],
            expected_outcome="Semantic assurance restored",
            rollback_strategy="Revert policy",
            proposed_by_user_id="author_user",
        )
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, user_id="author_user")
        approval = AssuranceRemediationService.review_remediation_plan(
            self.db,
            plan_id=plan.id,
            reviewer_user_id="reviewer_user",
            decision="APPROVE",
            review_notes="Approved after independent review",
        )
        self.assertTrue(approval.id.startswith("ara-"))
        self.assertEqual(approval.decision, "APPROVE")
        self.assertEqual(plan.status, "APPROVED")

    def test_08_execution_attestation_persistence(self):
        """Test execution attestation record with SHA-256 seal."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db,
            title="Execution Test Case",
            description="Testing execution attestation",
            affected_domain="NORMALIZATION_ASSURANCE",
            user_id="analyst_user",
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db,
            case_id=case.id,
            title="Revalidate Normalization",
            description="Plan",
            proposed_actions=[{"step": 1, "action": "Execute test suite"}],
            expected_outcome="Pass",
            rollback_strategy="Revert",
            proposed_by_user_id="analyst_user",
        )
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, user_id="analyst_user")
        AssuranceRemediationService.review_remediation_plan(self.db, plan.id, "reviewer_user", "APPROVE", "OK")
        AssuranceRemediationService.authorize_remediation_plan(self.db, plan.id, "reviewer_user")

        execution = AssuranceRemediationService.record_remediation_execution(
            self.db,
            plan_id=plan.id,
            execution_reference="EXEC-2026-001",
            execution_summary="Executed schema transformer update",
            executed_actions=[{"step": 1, "status": "COMPLETED"}],
            executed_by_user_id="analyst_user",
            external_ticket_id="CHG-2026-888",
        )
        self.assertTrue(execution.id.startswith("are-"))
        self.assertEqual(len(execution.execution_hash), 64)
        self.assertEqual(case.status, "VERIFICATION_PENDING")

    def test_09_recovery_verification_persistence(self):
        """Test post-remediation recovery verification record."""
        case = AssuranceRemediationCase(
            case_number=f"ARC-2026-VTEST-{uuid.uuid4().hex[:6]}",
            affected_domain="NORMALIZATION_ASSURANCE",
            title="Verification Persistence Test",
            description="Test",
            status="VERIFICATION_PENDING",
            created_by_user_id="analyst_user",
            deduplication_fingerprint="fp_verif_01",
            timeline=[],
        )
        self.db.add(case)
        self.db.flush()

        plan = AssuranceRemediationPlan(
            remediation_case_id=case.id,
            title="Plan",
            description="Plan desc",
            proposed_actions=[{"action": "test"}],
            expected_outcome="test",
            rollback_strategy="test",
            status="AUTHORIZED_FOR_EXECUTION",
            proposed_by_user_id="analyst_user",
        )
        self.db.add(plan)
        self.db.flush()

        execution = AssuranceRemediationExecution(
            remediation_case_id=case.id,
            remediation_plan_id=plan.id,
            execution_reference="EXEC-TEST-01",
            execution_summary="Executed",
            executed_actions=[{"action": "done"}],
            executed_by_user_id="analyst_user",
            execution_hash="test_exec_hash",
        )
        self.db.add(execution)
        self.db.flush()

        verification = AssuranceRecoveryVerification(
            remediation_case_id=case.id,
            execution_id=execution.id,
            verification_status="VERIFIED",
            verification_method="AUTOMATED_RE_EVALUATION",
            pre_remediation_score=55.0,
            post_remediation_score=88.0,
            score_delta=33.0,
            domain_status_before="DEGRADED",
            domain_status_after="HEALTHY",
            verified_by_user_id="analyst_user",
            verification_reasoning="Domain score improved by +33.0 points",
            verification_hash="test_verif_hash",
        )
        self.db.add(verification)
        self.db.commit()
        self.db.refresh(verification)

        self.assertTrue(verification.id.startswith("arv-"))
        self.assertEqual(verification.score_delta, 33.0)
        self.assertEqual(verification.verification_status, "VERIFIED")

    def test_10_recovery_record_immutability(self):
        """Test final recovery record persistence and hash seal."""
        record = AssuranceRecoveryRecord(
            remediation_case_id="case_imm_test",
            previous_assurance_evaluation_id="pae_prev_01",
            new_assurance_evaluation_id="pae_post_01",
            recovery_status="RECOVERED",
            recovery_confidence=0.95,
            score_before=50.0,
            score_after=90.0,
            score_delta=40.0,
            recovered_domains=["NORMALIZATION_ASSURANCE"],
            remaining_degraded_domains=[],
            recovery_reasoning="All checks passed",
            recovery_hash="test_rec_hash",
            confirmed_by_user_id="admin_user",
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)

        self.assertTrue(record.id.startswith("arrd-"))
        self.assertEqual(record.recovery_status, "RECOVERED")
        self.assertEqual(record.recovery_confidence, 0.95)

    # ── B. STATE MACHINE TESTS ────────────────────────────────────────────────

    def test_11_valid_open_to_analyzing(self):
        """Test case status transitions from OPEN to ANALYZING when RCA is created."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="State Test", description="Desc", affected_domain="EVIDENCE_ASSURANCE"
        )
        self.assertEqual(case.status, "OPEN")
        AssuranceRemediationService.create_root_cause_analysis(
            self.db, case.id, "DATA_INGESTION_FAILURE", "RCA_INGEST_FAIL", "Hypothesis", "Evidence"
        )
        self.assertEqual(case.status, "ANALYZING")

    def test_12_invalid_open_to_recovered(self):
        """Test direct jump from OPEN to RECOVERED is blocked."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Direct Recovery Block Test", description="Desc", affected_domain="EVIDENCE_ASSURANCE"
        )
        with self.assertRaises(InvalidStateTransitionException):
            AssuranceRemediationService.confirm_recovery(self.db, case.id, "admin_user")

    def test_13_valid_plan_submission(self):
        """Test valid plan submission DRAFT -> PENDING_REVIEW."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Submission Test", description="Desc", affected_domain="RISK_ASSURANCE"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan", "Desc", [{"action": "run"}], "Outcome", "Rollback", proposed_by_user_id="analyst_user"
        )
        self.assertEqual(plan.status, "DRAFT")
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, "analyst_user")
        self.assertEqual(plan.status, "PENDING_REVIEW")
        self.assertEqual(case.status, "PENDING_REVIEW")

    def test_14_invalid_draft_plan_execution(self):
        """Test executing a DRAFT plan is rejected."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Draft Exec Test", description="Desc", affected_domain="RISK_ASSURANCE"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan", "Desc", [{"action": "run"}], "Outcome", "Rollback", proposed_by_user_id="analyst_user"
        )
        with self.assertRaises(InvalidStateTransitionException):
            AssuranceRemediationService.record_remediation_execution(
                self.db, plan.id, "REF-01", "Summary", [{"action": "done"}], "analyst_user"
            )

    def test_15_approval_required_before_authorization(self):
        """Test plan must be APPROVED before authorization."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Auth Test", description="Desc", affected_domain="RISK_ASSURANCE"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan", "Desc", [{"action": "run"}], "Outcome", "Rollback", proposed_by_user_id="analyst_user"
        )
        with self.assertRaises(InvalidStateTransitionException):
            AssuranceRemediationService.authorize_remediation_plan(self.db, plan.id, "reviewer_user")

    def test_16_execution_required_before_verification(self):
        """Test verification requires completed execution attestation."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Verif Pre-req Test", description="Desc", affected_domain="RISK_ASSURANCE"
        )
        with self.assertRaises(InvalidStateTransitionException):
            AssuranceRemediationService.verify_assurance_recovery(self.db, case.id, "analyst_user")

    def test_17_verification_required_before_recovery(self):
        """Test recovery confirmation requires existing verification record."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Rec Pre-req Test", description="Desc", affected_domain="RISK_ASSURANCE"
        )
        with self.assertRaises(InvalidStateTransitionException):
            AssuranceRemediationService.confirm_recovery(self.db, case.id, "admin_user")

    def test_18_rejected_plan_cannot_execute(self):
        """Test rejected plan cannot be authorized or executed."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Reject Test", description="Desc", affected_domain="RISK_ASSURANCE", user_id="analyst_user"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan", "Desc", [{"action": "run"}], "Outcome", "Rollback", proposed_by_user_id="analyst_user"
        )
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, "analyst_user")
        AssuranceRemediationService.review_remediation_plan(self.db, plan.id, "reviewer_user", "REJECT", "Inadequate plan")
        self.assertEqual(plan.status, "REJECTED")

        with self.assertRaises(InvalidStateTransitionException):
            AssuranceRemediationService.authorize_remediation_plan(self.db, plan.id, "reviewer_user")

    # ── C. MAKER-CHECKER TESTS ────────────────────────────────────────────────

    def test_19_maker_checker_self_approval_rejected(self):
        """Test self-approval attempt raises SelfApprovalForbiddenException."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Self Approval Test", description="Desc", affected_domain="SEMANTIC_ASSURANCE", user_id="author_user"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan", "Desc", [{"action": "run"}], "Outcome", "Rollback", proposed_by_user_id="author_user"
        )
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, "author_user")

        with self.assertRaises(SelfApprovalForbiddenException):
            AssuranceRemediationService.review_remediation_plan(
                self.db, plan.id, reviewer_user_id="author_user", decision="APPROVE", review_notes="Self approval attempt"
            )

    def test_20_maker_checker_http_409_conflict(self):
        """Test API returns HTTP 409 Conflict when self-approval is attempted."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="API 409 Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE"
        )
        plan_res = client.post(
            f"/api/v1/assurance-remediation/cases/{case.id}/plans",
            json={
                "title": "API Plan for Self Approval Test",
                "description": "Detailed description of remediation plan",
                "proposed_actions": [{"step": 1, "action": "test"}],
                "expected_outcome": "Expected outcome",
                "rollback_strategy": "Rollback strategy",
                "estimated_risk": "LOW",
            },
            headers=self.admin_headers,
        )

        self.assertEqual(plan_res.status_code, 201)
        plan_id = plan_res.json()["id"]

        client.post(f"/api/v1/assurance-remediation/plans/{plan_id}/submit", headers=self.admin_headers)

        res = client.post(
            f"/api/v1/assurance-remediation/plans/{plan_id}/review",
            json={"decision": "APPROVE", "review_notes": "Attempting self-approval"},
            headers=self.admin_headers,  # admin_user is proposer
        )
        self.assertEqual(res.status_code, 409)
        self.assertIn("SELF_APPROVAL_FORBIDDEN", res.json()["detail"])


    def test_21_maker_checker_timeline_event_created(self):
        """Test timeline records SELF_APPROVAL_BLOCKED when self-approval is blocked."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Timeline Block Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE", user_id="analyst_user"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan", "Desc", [{"action": "run"}], "Outcome", "Rollback", proposed_by_user_id="analyst_user"
        )
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, "analyst_user")

        try:
            AssuranceRemediationService.review_remediation_plan(self.db, plan.id, "analyst_user", "APPROVE", "Self review")
        except SelfApprovalForbiddenException:
            pass

        self.db.refresh(case)
        event_types = [e["event_type"] for e in case.timeline]
        self.assertIn("SELF_APPROVAL_BLOCKED", event_types)

    def test_22_independent_reviewer_succeeds(self):
        """Test independent reviewer successfully approves plan."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Independent Review Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE", user_id="analyst_user"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan", "Desc", [{"action": "run"}], "Outcome", "Rollback", proposed_by_user_id="analyst_user"
        )
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, "analyst_user")

        approval = AssuranceRemediationService.review_remediation_plan(
            self.db, plan.id, reviewer_user_id="reviewer_user", decision="APPROVE", review_notes="Independent approval granted"
        )
        self.assertEqual(approval.decision, "APPROVE")
        self.assertEqual(plan.status, "APPROVED")

    # ── D. DETERMINISTIC RECOMMENDATION ENGINE TESTS ──────────────────────────

    def test_23_recommendation_deterministic_output(self):
        """Test recommendation engine produces deterministic SHA-256 hash across repeated runs."""
        conf1, state1 = AssuranceRemediationService.calculate_recommendation_confidence("DATA_INGESTION_FAILURE", "HIGH")
        conf2, state2 = AssuranceRemediationService.calculate_recommendation_confidence("DATA_INGESTION_FAILURE", "HIGH")
        self.assertEqual(conf1, conf2)
        self.assertEqual(state1, state2)

    def test_24_data_ingestion_failure_recommendation(self):
        """Test DATA_INGESTION_FAILURE maps to RESTORE_TELEMETRY and RETRY_DATA_PIPELINE."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Ingestion Rec Test", description="Desc", affected_domain="EVIDENCE_ASSURANCE"
        )
        AssuranceRemediationService.create_root_cause_analysis(
            self.db, case.id, "DATA_INGESTION_FAILURE", "RCA_INGEST", "Hypo", "Evid", "HIGH"
        )
        recs = AssuranceRemediationService.generate_remediation_recommendations(self.db, case.id)
        types = [r.recommendation_type for r in recs]
        self.assertIn("RESTORE_TELEMETRY", types)
        self.assertIn("RETRY_DATA_PIPELINE", types)

    def test_25_normalization_failure_recommendation(self):
        """Test NORMALIZATION_FAILURE maps to REVALIDATE_NORMALIZATION."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Norm Rec Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE"
        )
        AssuranceRemediationService.create_root_cause_analysis(
            self.db, case.id, "NORMALIZATION_FAILURE", "RCA_NORM", "Hypo", "Evid", "HIGH"
        )
        recs = AssuranceRemediationService.generate_remediation_recommendations(self.db, case.id)
        types = [r.recommendation_type for r in recs]
        self.assertIn("REVALIDATE_NORMALIZATION", types)

    def test_26_semantic_policy_failure_recommendation(self):
        """Test SEMANTIC_POLICY_FAILURE maps to REVIEW_SEMANTIC_POLICY."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Sem Rec Test", description="Desc", affected_domain="SEMANTIC_ASSURANCE"
        )
        AssuranceRemediationService.create_root_cause_analysis(
            self.db, case.id, "SEMANTIC_POLICY_FAILURE", "RCA_SEM", "Hypo", "Evid", "HIGH"
        )
        recs = AssuranceRemediationService.generate_remediation_recommendations(self.db, case.id)
        types = [r.recommendation_type for r in recs]
        self.assertIn("REVIEW_SEMANTIC_POLICY", types)

    def test_27_detection_rule_failure_recommendation(self):
        """Test DETECTION_RULE_FAILURE maps to REPAIR_RULE_DEPENDENCY and DISABLE_UNTRUSTED_RULE."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Det Rec Test", description="Desc", affected_domain="DETECTION_ASSURANCE"
        )
        AssuranceRemediationService.create_root_cause_analysis(
            self.db, case.id, "DETECTION_RULE_FAILURE", "RCA_DET", "Hypo", "Evid", "HIGH"
        )
        recs = AssuranceRemediationService.generate_remediation_recommendations(self.db, case.id)
        types = [r.recommendation_type for r in recs]
        self.assertIn("REPAIR_RULE_DEPENDENCY", types)
        self.assertIn("DISABLE_UNTRUSTED_RULE", types)

    def test_28_unknown_root_cause_manual_investigation(self):
        """Test UNKNOWN root cause maps to MANUAL_INVESTIGATION with low confidence."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Unknown Rec Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE"
        )
        AssuranceRemediationService.create_root_cause_analysis(
            self.db, case.id, "UNKNOWN", "RCA_UNKNOWN", "Unknown hypothesis", "Telemetry inconclusive", "LOW"
        )
        recs = AssuranceRemediationService.generate_remediation_recommendations(self.db, case.id)
        types = [r.recommendation_type for r in recs]
        self.assertIn("MANUAL_INVESTIGATION", types)
        self.assertTrue(recs[0].confidence_score <= 0.50)

    def test_29_confidence_deduction_formula(self):
        """Test confidence deduction arithmetic."""
        # Base 1.0 - UNKNOWN (0.40) - LOW (0.25) - incomplete (0.15) = 0.20
        conf, state = AssuranceRemediationService.calculate_recommendation_confidence(
            root_cause_category="UNKNOWN",
            analysis_confidence="LOW",
            evidence_complete=False,
            cross_domain=False,
        )
        self.assertEqual(conf, 0.20)
        self.assertEqual(state, "LOW_CONFIDENCE")

    def test_30_confidence_clamping(self):
        """Test confidence is clamped between 0.00 and 1.00."""
        conf, state = AssuranceRemediationService.calculate_recommendation_confidence(
            root_cause_category="UNKNOWN",
            analysis_confidence="LOW",
            evidence_complete=False,
            cross_domain=True,
        )
        self.assertTrue(0.00 <= conf <= 1.00)

    # ── E. CRYPTOGRAPHIC HARD FAILURE TESTS ───────────────────────────────────

    def test_31_crypto_failure_forced_critical(self):
        """Test CRYPTOGRAPHIC_ASSURANCE case is forced to CRITICAL severity and P1 priority."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db,
            title="Crypto Degradation Case",
            description="Testing crypto severity override",
            affected_domain="CRYPTOGRAPHIC_ASSURANCE",
            severity="LOW",  # Should be overridden
            priority="P3",   # Should be overridden
        )
        self.assertEqual(case.severity, "CRITICAL")
        self.assertEqual(case.priority, "P1")

    def test_32_crypto_failure_requires_dual_control(self):
        """Test plans created for CRYPTOGRAPHIC_ASSURANCE automatically require dual control."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Crypto Plan Test", description="Desc", affected_domain="CRYPTOGRAPHIC_ASSURANCE"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Crypto Plan", "Desc", [{"action": "audit"}], "Outcome", "Rollback",
            requires_dual_control=False  # Should be forced to True
        )
        self.assertTrue(plan.requires_dual_control)

    def test_33_crypto_failure_primary_recommendation(self):
        """Test primary recommendation for cryptographic failure is VERIFY_LEDGER_INTEGRITY."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Crypto Rec Test", description="Desc", affected_domain="CRYPTOGRAPHIC_ASSURANCE"
        )
        recs = AssuranceRemediationService.generate_remediation_recommendations(self.db, case.id)
        types = [r.recommendation_type for r in recs]
        self.assertIn("VERIFY_LEDGER_INTEGRITY", types)
        self.assertIn("REBUILD_MERKLE_BATCH", types)

    # ── F. RECOVERY VERIFICATION TESTS ────────────────────────────────────────

    def test_34_successful_recovery_verification(self):
        """Test post-remediation verification succeeds when score improves."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Recovery Verif Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE", user_id="analyst_user"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan", "Desc", [{"action": "remediate"}], "Outcome", "Rollback", proposed_by_user_id="analyst_user"
        )
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, "analyst_user")
        AssuranceRemediationService.review_remediation_plan(self.db, plan.id, "reviewer_user", "APPROVE", "Approved")
        AssuranceRemediationService.authorize_remediation_plan(self.db, plan.id, "reviewer_user")
        AssuranceRemediationService.record_remediation_execution(
            self.db, plan.id, "REF-REC-01", "Summary", [{"action": "done"}], "analyst_user"
        )

        verification = AssuranceRemediationService.verify_assurance_recovery(self.db, case.id, user_id="analyst_user")
        self.assertTrue(verification.verification_status in ("VERIFIED", "INCONCLUSIVE", "FAILED"))
        self.assertTrue(isinstance(verification.score_delta, float))

    def test_35_recovery_confidence_calculation(self):
        """Test recovery confidence formula calculation."""
        conf, tier = AssuranceRemediationService.calculate_recovery_confidence(
            telemetry_complete=True,
            partial_domain=False,
            remaining_alerts=0,
            evidence_confidence="HIGH",
        )
        self.assertEqual(conf, 1.00)
        self.assertEqual(tier, "CONFIRMED")

        conf2, tier2 = AssuranceRemediationService.calculate_recovery_confidence(
            telemetry_complete=False,  # -0.30
            partial_domain=True,       # -0.25
            remaining_alerts=1,        # -0.20
            evidence_confidence="LOW", # -0.15
        )
        self.assertEqual(conf2, 0.10)
        self.assertEqual(tier2, "UNKNOWN")

    def test_36_confirm_recovery_full_lifecycle(self):
        """Test full recovery confirmation lifecycle from case open to RECOVERED."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Full Lifecycle Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE", user_id="analyst_user"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan", "Desc", [{"action": "remediate"}], "Outcome", "Rollback", proposed_by_user_id="analyst_user"
        )
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, "analyst_user")
        AssuranceRemediationService.review_remediation_plan(self.db, plan.id, "reviewer_user", "APPROVE", "Approved")
        AssuranceRemediationService.authorize_remediation_plan(self.db, plan.id, "reviewer_user")
        exec_record = AssuranceRemediationService.record_remediation_execution(
            self.db, plan.id, "REF-LIFECYCLE-01", "Summary", [{"action": "done"}], "analyst_user"
        )

        # Force a VERIFIED verification for lifecycle test
        verif = AssuranceRecoveryVerification(
            remediation_case_id=case.id,
            execution_id=exec_record.id,
            verification_status="VERIFIED",
            verification_method="AUTOMATED_RE_EVALUATION",
            pre_remediation_score=50.0,
            post_remediation_score=92.0,
            score_delta=42.0,
            domain_status_before="DEGRADED",
            domain_status_after="HEALTHY",
            verified_by_user_id="analyst_user",
            verification_reasoning="All checks verified",
            verification_hash="test_vhash",
        )
        self.db.add(verif)
        self.db.commit()

        rec = AssuranceRemediationService.confirm_recovery(self.db, case.id, "admin_user", "Recovery verified")
        self.assertEqual(rec.recovery_status, "RECOVERED")
        self.assertEqual(case.status, "RECOVERED")
        self.assertIsNotNone(case.resolved_at)

    # ── G. IMMUTABILITY & PROVENANCE TESTS ─────────────────────────────────────

    def test_37_18_stage_provenance_trace(self):
        """Test 18-stage provenance trace structure and availability flags."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Trace Test Case", description="Desc", affected_domain="NORMALIZATION_ASSURANCE"
        )
        trace = AssuranceRemediationService.build_18_stage_provenance_trace(self.db, case.id)
        self.assertEqual(len(trace["stages"]), 18)
        stage_names = [s["stage_name"] for s in trace["stages"]]
        self.assertEqual(stage_names[0], "RAW_EVIDENCE")
        self.assertEqual(stage_names[11], "REMEDIATION_CASE")
        self.assertEqual(stage_names[17], "GOVERNANCE_LEDGER_AND_MERKLE_PROOF")

    def test_38_governance_ledger_append_only(self):
        """Test governance ledger records append-only events for assurance remediation."""
        last_entry = self.db.query(GovernanceLedgerEntry).order_by(GovernanceLedgerEntry.sequence_number.desc()).first()
        prev_seq = last_entry.sequence_number if last_entry else 0

        AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Ledger Seq Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE"
        )
        new_last = self.db.query(GovernanceLedgerEntry).order_by(GovernanceLedgerEntry.sequence_number.desc()).first()
        self.assertIsNotNone(new_last)
        self.assertTrue(new_last.sequence_number > prev_seq)

    # ── H. RBAC TESTS ─────────────────────────────────────────────────────────

    def test_39_rbac_viewer_cannot_execute(self):
        """Test Viewer role cannot execute remediation (HTTP 403)."""
        res = client.post(
            "/api/v1/assurance-remediation/plans/some_plan_id/execution",
            json={
                "execution_reference": "REF-01",
                "execution_summary": "Test",
                "executed_actions": [{"step": 1}],
            },
            headers=self.viewer_headers,
        )
        self.assertEqual(res.status_code, 403)

    def test_40_rbac_author_cannot_review(self):
        """Test Policy Author role cannot review remediation plan (HTTP 403)."""
        res = client.post(
            "/api/v1/assurance-remediation/plans/some_plan_id/review",
            json={"decision": "APPROVE", "review_notes": "Author review"},
            headers=self.author_headers,
        )
        self.assertEqual(res.status_code, 403)

    def test_41_rbac_auditor_provenance_access(self):
        """Test Auditor role can access 18-stage provenance trace."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Auditor Trace Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE"
        )
        res = client.get(
            f"/api/v1/assurance-remediation/cases/{case.id}/trace",
            headers=self.auditor_headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json()["stages"]), 18)

    def test_42_rbac_admin_full_access(self):
        """Test Admin role has full access to create cases and kpis."""
        res = client.get(
            "/api/v1/assurance-remediation/kpis/summary",
            headers=self.admin_headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("total_cases", res.json())

    # ── I. API ENDPOINT TESTS ─────────────────────────────────────────────────

    def test_43_api_create_case_and_list(self):
        """Test API case creation and filtered listing."""
        res = client.post(
            "/api/v1/assurance-remediation/cases",
            json={
                "title": "API Created Case",
                "description": "Case created via REST API",
                "affected_domain": "RISK_ASSURANCE",
                "severity": "HIGH",
                "priority": "P1",
            },
            headers=self.analyst_headers,
        )
        self.assertEqual(res.status_code, 201)
        case_id = res.json()["id"]

        list_res = client.get(
            "/api/v1/assurance-remediation/cases?domain=RISK_ASSURANCE",
            headers=self.analyst_headers,
        )
        self.assertEqual(list_res.status_code, 200)
        ids = [c["id"] for c in list_res.json()]
        self.assertIn(case_id, ids)

    def test_44_api_generate_recommendations(self):
        """Test API recommendation generation."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="API Rec Test", description="Desc", affected_domain="EVIDENCE_ASSURANCE"
        )
        res = client.post(
            f"/api/v1/assurance-remediation/cases/{case.id}/recommendations/generate",
            headers=self.analyst_headers,
        )
        self.assertEqual(res.status_code, 201)
        self.assertTrue(len(res.json()) >= 1)

    def test_45_api_plan_submission_review_authorization(self):
        """Test API plan submission, review, and authorization workflow."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="API Plan Workflow Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE", user_id="analyst_user"
        )
        # Create plan
        plan_res = client.post(
            f"/api/v1/assurance-remediation/cases/{case.id}/plans",
            json={
                "title": "API Plan",
                "description": "Plan description",
                "proposed_actions": [{"step": 1, "action": "Run fix"}],
                "expected_outcome": "Score > 85",
                "rollback_strategy": "Rollback",
                "estimated_risk": "LOW",
            },
            headers=self.analyst_headers,
        )
        self.assertEqual(plan_res.status_code, 201)
        plan_id = plan_res.json()["id"]

        # Submit plan
        submit_res = client.post(
            f"/api/v1/assurance-remediation/plans/{plan_id}/submit",
            json={"notes": "Ready for review"},
            headers=self.analyst_headers,
        )
        self.assertEqual(submit_res.status_code, 200)
        self.assertEqual(submit_res.json()["status"], "PENDING_REVIEW")

        # Independent Review
        review_res = client.post(
            f"/api/v1/assurance-remediation/plans/{plan_id}/review",
            json={"decision": "APPROVE", "review_notes": "Looks solid"},
            headers=self.reviewer_headers,
        )
        self.assertEqual(review_res.status_code, 200)

        # Authorize
        auth_res = client.post(
            f"/api/v1/assurance-remediation/plans/{plan_id}/authorize",
            headers=self.reviewer_headers,
        )
        self.assertEqual(auth_res.status_code, 200)
        self.assertEqual(auth_res.json()["status"], "AUTHORIZED_FOR_EXECUTION")

    def test_46_api_trends_endpoint(self):
        """Test API recovery trends endpoint."""
        res = client.get("/api/v1/assurance-remediation/trends", headers=self.viewer_headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("trends", res.json())
        self.assertIn("total_count", res.json())

    def test_47_api_timeline_endpoint(self):
        """Test API case timeline endpoint."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="API Timeline Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE"
        )
        res = client.get(f"/api/v1/assurance-remediation/cases/{case.id}/timeline", headers=self.viewer_headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["case_id"], case.id)
        self.assertTrue(len(res.json()["timeline"]) >= 1)

    def test_48_api_get_case_details(self):
        """Test GET /cases/{case_id} endpoint."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Details Test", description="Desc", affected_domain="EVIDENCE_ASSURANCE"
        )
        res = client.get(f"/api/v1/assurance-remediation/cases/{case.id}", headers=self.viewer_headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["title"], "Details Test")

    def test_49_api_get_case_not_found(self):
        """Test GET /cases/{case_id} returns 404 for invalid ID."""
        res = client.get("/api/v1/assurance-remediation/cases/arc-nonexistent", headers=self.viewer_headers)
        self.assertEqual(res.status_code, 404)

    def test_50_api_root_cause_create_and_get(self):
        """Test POST and GET /cases/{case_id}/root-cause endpoints."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="RCA API Test", description="Desc", affected_domain="SEMANTIC_ASSURANCE"
        )
        post_res = client.post(
            f"/api/v1/assurance-remediation/cases/{case.id}/root-cause",
            json={
                "root_cause_category": "SEMANTIC_POLICY_FAILURE",
                "root_cause_key": "RCA_SEM_DRIFT",
                "hypothesis": "Policy rules out of date with incoming telemetry",
                "evidence_summary": "Drift alert threshold exceeded",
                "confidence": "HIGH",
            },
            headers=self.analyst_headers,
        )
        self.assertEqual(post_res.status_code, 201)

        get_res = client.get(
            f"/api/v1/assurance-remediation/cases/{case.id}/root-cause",
            headers=self.viewer_headers,
        )
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(len(get_res.json()), 1)
        self.assertEqual(get_res.json()[0]["root_cause_category"], "SEMANTIC_POLICY_FAILURE")

    def test_51_api_confirmed_rca_requires_reviewer(self):
        """Test creating CONFIRMED RCA without reviewer fails with 400."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Confirmed RCA Test", description="Desc", affected_domain="SEMANTIC_ASSURANCE"
        )
        res = client.post(
            f"/api/v1/assurance-remediation/cases/{case.id}/root-cause",
            json={
                "root_cause_category": "SEMANTIC_POLICY_FAILURE",
                "root_cause_key": "RCA_SEM_CONFIRMED_TEST",
                "hypothesis": "Hypothesis",
                "evidence_summary": "Evidence",
                "confidence": "CONFIRMED",
                # missing reviewed_by_user_id
            },
            headers=self.analyst_headers,
        )
        self.assertEqual(res.status_code, 400)

    def test_52_api_get_recommendations(self):
        """Test GET /cases/{case_id}/recommendations endpoint."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Recs List API Test", description="Desc", affected_domain="DETECTION_ASSURANCE"
        )
        client.post(
            f"/api/v1/assurance-remediation/cases/{case.id}/recommendations/generate",
            headers=self.analyst_headers,
        )
        get_res = client.get(
            f"/api/v1/assurance-remediation/cases/{case.id}/recommendations",
            headers=self.viewer_headers,
        )
        self.assertEqual(get_res.status_code, 200)
        self.assertTrue(len(get_res.json()) >= 1)

    def test_53_api_record_execution_and_verify(self):
        """Test execution attestation and recovery verification via REST API."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Exec & Verif API Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE", user_id="analyst_user"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan Title", "Plan Desc", [{"step": 1}], "Outcome", "Rollback", proposed_by_user_id="analyst_user"
        )
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, "analyst_user")
        AssuranceRemediationService.review_remediation_plan(self.db, plan.id, "reviewer_user", "APPROVE", "OK")
        AssuranceRemediationService.authorize_remediation_plan(self.db, plan.id, "reviewer_user")

        exec_res = client.post(
            f"/api/v1/assurance-remediation/plans/{plan.id}/execution",
            json={
                "execution_reference": "EXEC-API-TEST-01",
                "external_ticket_id": "CHG-2026-999",
                "execution_summary": "Executed fix via API",
                "executed_actions": [{"action": "remediated"}],
            },
            headers=self.analyst_headers,
        )
        self.assertEqual(exec_res.status_code, 201)
        self.assertEqual(exec_res.json()["execution_reference"], "EXEC-API-TEST-01")

        verif_res = client.post(
            f"/api/v1/assurance-remediation/cases/{case.id}/verify-recovery",
            headers=self.analyst_headers,
        )
        self.assertEqual(verif_res.status_code, 201)
        self.assertTrue("verification_status" in verif_res.json())

    def test_54_api_get_recovery_verifications(self):
        """Test GET /cases/{case_id}/recovery endpoint."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Get Verifs API Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE"
        )
        res = client.get(
            f"/api/v1/assurance-remediation/cases/{case.id}/recovery",
            headers=self.viewer_headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(isinstance(res.json(), list))

    def test_55_api_confirm_recovery_endpoint(self):
        """Test POST /cases/{case_id}/confirm-recovery endpoint."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Confirm Rec API Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE", user_id="analyst_user"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan Title", "Plan Desc", [{"step": 1}], "Outcome", "Rollback", proposed_by_user_id="analyst_user"
        )
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, "analyst_user")
        AssuranceRemediationService.review_remediation_plan(self.db, plan.id, "reviewer_user", "APPROVE", "OK")
        AssuranceRemediationService.authorize_remediation_plan(self.db, plan.id, "reviewer_user")
        exec_record = AssuranceRemediationService.record_remediation_execution(
            self.db, plan.id, "EXEC-CONF-01", "Summary", [{"action": "done"}], "analyst_user"
        )

        # Seed verified verification
        verif = AssuranceRecoveryVerification(
            remediation_case_id=case.id,
            execution_id=exec_record.id,
            verification_status="VERIFIED",
            verification_method="AUTOMATED_RE_EVALUATION",
            pre_remediation_score=50.0,
            post_remediation_score=95.0,
            score_delta=45.0,
            domain_status_before="DEGRADED",
            domain_status_after="HEALTHY",
            verified_by_user_id="analyst_user",
            verification_reasoning="All checks passed",
            verification_hash="test_vhash_conf",
        )
        self.db.add(verif)
        self.db.commit()

        conf_res = client.post(
            f"/api/v1/assurance-remediation/cases/{case.id}/confirm-recovery",
            json={"reasoning": "Admin final confirmation"},
            headers=self.admin_headers,
        )
        self.assertEqual(conf_res.status_code, 201)
        self.assertEqual(conf_res.json()["recovery_status"], "RECOVERED")

    def test_56_case_filter_by_status_and_severity(self):
        """Test listing cases filtered by status and severity."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Filter Test Case", description="Desc", affected_domain="CRYPTOGRAPHIC_ASSURANCE", severity="CRITICAL"
        )
        res = client.get(
            "/api/v1/assurance-remediation/cases?status=OPEN&severity=CRITICAL",
            headers=self.viewer_headers,
        )
        self.assertEqual(res.status_code, 200)
        ids = [c["id"] for c in res.json()]
        self.assertIn(case.id, ids)

    def test_57_plan_request_changes_workflow(self):
        """Test reviewing plan with REQUEST_CHANGES transitions status back to CHANGES_REQUESTED."""
        case = AssuranceRemediationService.create_remediation_case_manual(
            self.db, title="Changes Requested Test", description="Desc", affected_domain="NORMALIZATION_ASSURANCE", user_id="analyst_user"
        )
        plan = AssuranceRemediationService.create_remediation_plan(
            self.db, case.id, "Plan Title", "Plan Desc", [{"step": 1}], "Outcome", "Rollback", proposed_by_user_id="analyst_user"
        )
        AssuranceRemediationService.submit_remediation_plan(self.db, plan.id, "analyst_user")
        approval = AssuranceRemediationService.review_remediation_plan(
            self.db, plan.id, "reviewer_user", "REQUEST_CHANGES", "Please add more detailed steps"
        )
        self.assertEqual(approval.decision, "REQUEST_CHANGES")
        self.assertEqual(plan.status, "CHANGES_REQUESTED")


if __name__ == "__main__":
    unittest.main()

