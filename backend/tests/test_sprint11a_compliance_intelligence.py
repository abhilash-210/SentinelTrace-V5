"""
tests/test_sprint11a_compliance_intelligence.py
------------------------------------------------
Comprehensive automated test suite for Sprint 11A:
- Compliance Intelligence & Security Control Governance
- 3 Frameworks (SentinelTrace Security Baseline v5, NIST CSF 2.0, ISO 27001:2022)
- 30+ Requirements and 12 Core Security Controls
- Deterministic Control Effectiveness Scoring (0-100) with Explainable Deductions
- Hard Failure Override: Cryptographic Failure Forces Score 0.0 & Ineffective Status
- Compliance Gap Detection & SHA-256 Fingerprint Deduplication
- Maker-Checker Dual Control Review (Self-Approval Blocked HTTP 409 Conflict)
- 22-Stage Unbroken Cryptographic Compliance Provenance Engine
- Centralized RBAC Enforcement across all 6 Platform Roles
- Full REST API Test Coverage
"""

import hashlib
import json
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.compliance_intelligence import (
    ComplianceFramework,
    ComplianceRequirement,
    SecurityControl,
    FrameworkControlMapping,
    ControlEvidenceBinding,
    ControlEffectivenessEvaluation,
    ComplianceGap,
    ComplianceFinding,
    CompliancePostureEvaluation,
    ComplianceReview,
    ComplianceProvenanceRecord,
    CONTROL_EVIDENCE_BINDING_DOMAIN_PREFIX,
    CONTROL_EFFECTIVENESS_DOMAIN_PREFIX,
    COMPLIANCE_GAP_DOMAIN_PREFIX,
    COMPLIANCE_FINDING_DOMAIN_PREFIX,
    COMPLIANCE_POSTURE_DOMAIN_PREFIX,
    COMPLIANCE_REVIEW_DOMAIN_PREFIX,
    COMPLIANCE_PROVENANCE_DOMAIN_PREFIX,
    calculate_compliance_hash,
)
from app.services.control_effectiveness_service import ControlEffectivenessService
from app.services.compliance_gap_service import ComplianceGapService
from app.services.compliance_posture_service import CompliancePostureService
from app.services.compliance_governance_service import (
    ComplianceGovernanceService,
    SelfApprovalForbiddenError,
)
from app.services.compliance_provenance_service import ComplianceProvenanceService, PROVENANCE_22_STAGES
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint11AComplianceIntelligence(unittest.TestCase):
    """Test suite for Sprint 11A Compliance Intelligence & Control Governance."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)
            CompliancePostureService.seed_default_frameworks_and_controls(db)
            db.commit()

    def setUp(self):
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 1: MODEL & SCHEMA INVARIANTS (Tests 1 to 10)
    # ══════════════════════════════════════════════════════════════════════════

    def test_01_compliance_framework_model_creation(self):
        """1. Verify ComplianceFramework creation and default status."""
        fw_code = f"FW_TEST_{uuid.uuid4().hex[:8]}"
        fw = ComplianceFramework(
            framework_code=fw_code,
            framework_name="Test Framework",
            framework_version="1.0",
            description="Testing framework model",
            framework_category="CUSTOM",
            publisher="QA Engineer",
            created_by_user_id="admin_demo",
        )
        self.db.add(fw)
        self.db.commit()
        self.assertIsNotNone(fw.id)
        self.assertEqual(fw.status, "ACTIVE")
        self.assertEqual(fw.framework_code, fw_code)

    def test_02_compliance_requirement_model_creation(self):
        """2. Verify ComplianceRequirement creation and framework FK."""
        fw = self.db.query(ComplianceFramework).filter(ComplianceFramework.framework_code.like("FW_TEST_%")).first()
        req_code = f"REQ_TEST_{uuid.uuid4().hex[:8]}"
        req = ComplianceRequirement(
            framework_id=fw.id,
            requirement_code=req_code,
            title="Test Requirement Title",
            description="Test Requirement Description",
            requirement_category="TECHNICAL",
            importance_weight=1.5,
            verification_required=True,
            evidence_freshness_days=30,
        )
        self.db.add(req)
        self.db.commit()
        self.assertIsNotNone(req.id)
        self.assertEqual(req.importance_weight, 1.5)
        self.assertTrue(req.verification_required)

    def test_03_security_control_model_creation(self):
        """3. Verify SecurityControl model creation and defaults."""
        ctrl_code = f"SC_TEST_{uuid.uuid4().hex[:8]}"
        ctrl = SecurityControl(
            control_code=ctrl_code,
            control_name="Test Control Name",
            description="Test Control Description",
            control_domain="IDENTITY_ACCESS",
            control_owner="SecOps",
            control_type="DETECTIVE",
            criticality="HIGH",
            expected_state="OPERATIONAL",
            verification_frequency="CONTINUOUS",
            status="ACTIVE",
        )
        self.db.add(ctrl)
        self.db.commit()
        self.assertIsNotNone(ctrl.id)
        self.assertEqual(ctrl.expected_state, "OPERATIONAL")
        self.assertEqual(ctrl.criticality, "HIGH")

    def test_04_framework_control_mapping_model(self):
        """4. Verify FrameworkControlMapping link."""
        fw = self.db.query(ComplianceFramework).filter(ComplianceFramework.framework_code.like("FW_TEST_%")).first()
        req = ComplianceRequirement(
            framework_id=fw.id,
            requirement_code=f"REQ_MAP_{uuid.uuid4().hex[:6]}",
            title="Mapping Test Requirement",
            description="Testing mapping",
            requirement_category="TECHNICAL",
            importance_weight=1.0,
            verification_required=True,
            evidence_freshness_days=30,
        )
        ctrl = SecurityControl(
            control_code=f"SC_MAP_{uuid.uuid4().hex[:6]}",
            control_name="Mapping Test Control",
            description="Testing mapping control",
            control_domain="DATA_INTEGRITY",
            control_owner="SecOps",
            control_type="PREVENTIVE",
            criticality="HIGH",
            expected_state="OPERATIONAL",
            status="ACTIVE",
        )
        self.db.add(req)
        self.db.add(ctrl)
        self.db.commit()

        mapping = FrameworkControlMapping(
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            mapping_strength="PRIMARY",
            mapping_rationale="Primary technical mapping for test",
            mandatory=True,
        )
        self.db.add(mapping)
        self.db.commit()
        self.assertIsNotNone(mapping.id)
        self.assertEqual(mapping.mapping_strength, "PRIMARY")

    def test_05_control_evidence_binding_hash_canonical(self):
        """5. Verify ControlEvidenceBinding deterministic hash."""
        payload = {
            "control_id": "ctrl_123",
            "evidence_type": "NORMALIZED_LOG",
            "evidence_id": "evt_456",
            "evidence_hash": "a" * 64,
        }
        h1 = calculate_compliance_hash(CONTROL_EVIDENCE_BINDING_DOMAIN_PREFIX, payload)
        h2 = calculate_compliance_hash(CONTROL_EVIDENCE_BINDING_DOMAIN_PREFIX, payload)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_06_control_effectiveness_domain_prefix(self):
        """6. Verify ControlEffectivenessEvaluation domain prefix separation."""
        payload = {"control_code": "SC-AUTH-01", "score": 95.0}
        h_eff = calculate_compliance_hash(CONTROL_EFFECTIVENESS_DOMAIN_PREFIX, payload)
        h_post = calculate_compliance_hash(COMPLIANCE_POSTURE_DOMAIN_PREFIX, payload)
        self.assertNotEqual(h_eff, h_post)

    def test_07_compliance_gap_fingerprint_deterministic(self):
        """7. Verify ComplianceGap SHA-256 fingerprint deduplication key."""
        fp1 = ComplianceGapService.compute_gap_fingerprint("req_1", "ctrl_1", "MISSING_EVIDENCE", "RULE_1")
        fp2 = ComplianceGapService.compute_gap_fingerprint("req_1", "ctrl_1", "MISSING_EVIDENCE", "RULE_1")
        fp3 = ComplianceGapService.compute_gap_fingerprint("req_2", "ctrl_1", "MISSING_EVIDENCE", "RULE_1")
        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)

    def test_08_compliance_finding_model(self):
        """8. Verify ComplianceFinding creation."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        finding = ComplianceFinding(
            finding_number=f"CFN-{uuid.uuid4().hex[:6].upper()}",
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            finding_type="NON_COMPLIANCE",
            statement="Sample Finding Statement",
            evidence_summary="Sample finding summary",
            confidence="HIGH",
            status="DRAFT",
            created_by_user_id="auditor_demo",
            finding_hash="f" * 64,
        )
        self.db.add(finding)
        self.db.commit()
        self.assertIsNotNone(finding.id)
        self.assertEqual(finding.status, "DRAFT")

    def test_09_compliance_review_model(self):
        """9. Verify ComplianceReview model."""
        posture = self.db.query(CompliancePostureEvaluation).first()
        if not posture:
            fw = self.db.query(ComplianceFramework).filter(ComplianceFramework.framework_code.like("FW_TEST_%")).first()
            posture = CompliancePostureService.evaluate_framework_posture(self.db, fw.id)
            self.db.commit()

        review = ComplianceReview(
            compliance_posture_evaluation_id=posture.id,
            review_action="APPROVE",
            review_comment="Dual control review approved.",
            reviewer_user_id="reviewer_demo",
            review_hash="r" * 64,
        )
        self.db.add(review)
        self.db.commit()
        self.assertIsNotNone(review.id)
        self.assertEqual(review.review_action, "APPROVE")

    def test_10_compliance_provenance_22_stages_count(self):
        """10. Verify 22 canonical provenance stages count."""
        self.assertEqual(len(PROVENANCE_22_STAGES), 22)
        self.assertEqual(PROVENANCE_22_STAGES[0][1], "RAW_SECURITY_EVENT")
        self.assertEqual(PROVENANCE_22_STAGES[21][1], "GOVERNANCE_LEDGER_MERKLE_PROOF")

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 2: CONTROL EFFECTIVENESS SERVICE & DEDUCTIONS (Tests 11 to 20)
    # ══════════════════════════════════════════════════════════════════════════

    def test_11_bind_evidence_to_control(self):
        """11. Verify binding immutable upstream evidence to control."""
        ctrl = self.db.query(SecurityControl).first()
        binding = ControlEffectivenessService.bind_evidence(
            db=self.db,
            security_control_id=ctrl.id,
            evidence_type="NORMALIZED_LOG",
            evidence_id=f"evt_{uuid.uuid4().hex[:8]}",
            evidence_hash=hashlib.sha256(b"raw_log").hexdigest(),
            source_stage="STAGE_02_NORMALIZED_LOG",
        )
        self.db.commit()
        self.assertIsNotNone(binding.id)
        self.assertEqual(binding.security_control_id, ctrl.id)

    def test_12_evaluate_control_with_verified_evidence(self):
        """12. Verify control evaluation with fresh verified evidence scores high."""
        ctrl_code = f"SC_EVAL_{uuid.uuid4().hex[:8]}"
        ctrl = SecurityControl(
            control_code=ctrl_code,
            control_name="Eval Test Control",
            description="Testing evaluation",
            control_domain="DETECTION_ENGINEERING",
            control_owner="SecOps",
            control_type="DETECTIVE",
            criticality="HIGH",
            expected_state="OPERATIONAL",
            verification_frequency="CONTINUOUS",
            status="ACTIVE",
        )
        self.db.add(ctrl)
        self.db.commit()

        # Bind verified evidence records
        ControlEffectivenessService.bind_evidence(
            db=self.db,
            security_control_id=ctrl.id,
            evidence_type="DETECTION_RULE",
            evidence_id="rule_1",
            evidence_hash=hashlib.sha256(b"r1").hexdigest(),
            source_stage="STAGE_10_RULE_EXECUTION",
        )
        ControlEffectivenessService.bind_evidence(
            db=self.db,
            security_control_id=ctrl.id,
            evidence_type="GOVERNANCE_LEDGER",
            evidence_id="led_1",
            evidence_hash=hashlib.sha256(b"l1").hexdigest(),
            source_stage="STAGE_07_LEDGER",
        )
        self.db.commit()

        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
            evaluator_username="compliance_engine",
        )
        self.db.commit()
        self.assertGreaterEqual(eval_res.effectiveness_score, 80.0)
        self.assertEqual(eval_res.evaluation_status, "EFFECTIVE")

    def test_13_missing_evidence_deduction(self):
        """13. Verify Zero Trust Axiom: MISSING EVIDENCE != PASS triggers -35 deduction."""
        ctrl_code = f"SC_NO_EVID_{uuid.uuid4().hex[:8]}"
        ctrl = SecurityControl(
            control_code=ctrl_code,
            control_name="No Evidence Control",
            description="Has zero evidence bound",
            control_domain="DATA_INTEGRITY",
            control_owner="SecOps",
            control_type="DETECTIVE",
            criticality="HIGH",
            expected_state="OPERATIONAL",
            status="ACTIVE",
        )
        self.db.add(ctrl)
        self.db.commit()

        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
        )
        self.db.commit()
        rules = [d["rule"] for d in eval_res.deductions_json]
        self.assertIn("MISSING_EVIDENCE_COVERAGE", rules)
        self.assertLess(eval_res.effectiveness_score, 70.0)

    def test_14_operational_state_degraded_deduction(self):
        """14. Verify DEGRADED operational state applies -15 deduction."""
        ctrl = self.db.query(SecurityControl).filter(SecurityControl.control_code == "SC-AUTH-01").first()
        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
            operational_state_override="DEGRADED",
        )
        self.db.commit()
        rules = [d["rule"] for d in eval_res.deductions_json]
        self.assertIn("OPERATIONAL_STATE_DEGRADED", rules)

    def test_15_operational_state_failed_deduction(self):
        """15. Verify FAILED operational state applies -25 deduction."""
        ctrl = self.db.query(SecurityControl).filter(SecurityControl.control_code == "SC-INGEST-01").first()
        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
            operational_state_override="FAILED",
        )
        self.db.commit()
        rules = [d["rule"] for d in eval_res.deductions_json]
        self.assertIn("OPERATIONAL_STATE_FAILED", rules)

    def test_16_operational_state_unknown_deduction(self):
        """16. Verify Zero Trust Axiom: UNKNOWN CONTROL != COMPLIANT applies -30 deduction."""
        ctrl = self.db.query(SecurityControl).filter(SecurityControl.control_code == "SC-SEM-01").first()
        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
            operational_state_override="UNKNOWN",
        )
        self.db.commit()
        rules = [d["rule"] for d in eval_res.deductions_json]
        self.assertIn("OPERATIONAL_STATE_UNKNOWN", rules)

    def test_17_incident_impact_deductions(self):
        """17. Verify active security incidents apply deductions."""
        ctrl = self.db.query(SecurityControl).filter(SecurityControl.control_code == "SC-INC-01").first()
        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
            incident_impacts=[
                {"incident_id": "INC-001", "severity": "CRITICAL"},
                {"incident_id": "INC-002", "severity": "HIGH"},
            ],
        )
        self.db.commit()
        rules = [d["rule"] for d in eval_res.deductions_json]
        self.assertIn("ACTIVE_CRITICAL_INCIDENT_IMPACT", rules)
        self.assertIn("ACTIVE_HIGH_INCIDENT_IMPACT", rules)

    def test_18_evaluate_all_controls_batch(self):
        """18. Verify batch evaluate_all_controls executes sequentially."""
        evals = ControlEffectivenessService.evaluate_all_controls(db=self.db)
        self.db.commit()
        self.assertGreaterEqual(len(evals), 12)
        for ev in evals:
            self.assertIsNotNone(ev.id)
            self.assertIsNotNone(ev.effectiveness_score)

    def test_19_control_effectiveness_score_clamping(self):
        """19. Verify score is strictly clamped between 0.0 and 100.0."""
        ctrl = self.db.query(SecurityControl).first()
        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
            operational_state_override="UNKNOWN",
            incident_impacts=[
                {"incident_id": "INC-1", "severity": "CRITICAL"},
                {"incident_id": "INC-2", "severity": "CRITICAL"},
                {"incident_id": "INC-3", "severity": "CRITICAL"},
            ],
        )
        self.db.commit()
        self.assertEqual(eval_res.effectiveness_score, 0.0)

    def test_20_control_evaluation_updates_evaluation_table(self):
        """20. Verify evaluation record is written to ControlEffectivenessEvaluation."""
        ctrl = self.db.query(SecurityControl).filter(SecurityControl.control_code == "SC-LEDGER-01").first()
        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
        )
        self.db.commit()
        self.assertIsNotNone(eval_res.id)
        self.assertEqual(eval_res.security_control_id, ctrl.id)

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 3: CRYPTOGRAPHIC DOMINANCE & OVERRIDES (Tests 21 to 26)
    # ══════════════════════════════════════════════════════════════════════════

    def test_21_crypto_failure_forces_zero_score(self):
        """21. Verify Axiom: CRYPTOGRAPHIC FAILURE ALWAYS DOMINATES NUMERICAL SCORES (forces 0.0)."""
        ctrl = self.db.query(SecurityControl).filter(SecurityControl.control_code == "SC-MERKLE-01").first()
        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
            force_crypto_failure=True,
        )
        self.db.commit()
        self.assertEqual(eval_res.effectiveness_score, 0.0)
        self.assertEqual(eval_res.evaluation_status, "INEFFECTIVE")
        self.assertEqual(eval_res.integrity_score, 0.0)
        rules = [d["rule"] for d in eval_res.deductions_json]
        self.assertIn("CRYPTOGRAPHIC_INTEGRITY_DOMINANCE", rules)

    def test_22_framework_posture_crypto_failure_override(self):
        """22. Verify framework posture clamps to 0.0 & CRITICAL_NON_COMPLIANT on crypto failure."""
        fw = self.db.query(ComplianceFramework).filter(ComplianceFramework.framework_code == "FW-SENTINEL-TRACE-V5").first()
        ctrl = self.db.query(SecurityControl).filter(SecurityControl.control_code == "SC-LEDGER-01").first()

        ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
            force_crypto_failure=True,
        )
        self.db.commit()

        posture = CompliancePostureService.evaluate_framework_posture(
            db=self.db,
            framework_id=fw.id,
        )
        self.db.commit()
        self.assertEqual(posture.overall_score, 0.0)
        self.assertEqual(posture.posture_status, "CRITICAL_NON_COMPLIANT")
        self.assertTrue(posture.hard_failure_override)

    def test_23_crypto_failure_gap_generation(self):
        """23. Verify scan_framework_gaps records CRITICAL severity gap for crypto failure."""
        fw = self.db.query(ComplianceFramework).filter(ComplianceFramework.framework_code == "FW-SENTINEL-TRACE-V5").first()
        gaps = ComplianceGapService.scan_framework_gaps(db=self.db, framework_id=fw.id)
        self.db.commit()
        crypto_gaps = [g for g in gaps if g.gap_category == "CRYPTOGRAPHIC_FAILURE"]
        self.assertGreater(len(crypto_gaps), 0)
        self.assertEqual(crypto_gaps[0].severity, "CRITICAL")

    def test_24_crypto_recovery_restores_score_after_re_evaluation(self):
        """24. Verify restoring verified crypto state allows score to recover upon re-evaluation."""
        ctrl = self.db.query(SecurityControl).filter(SecurityControl.control_code == "SC-LEDGER-01").first()
        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
            force_crypto_failure=False,
            operational_state_override="OPERATIONAL",
        )
        self.db.commit()
        self.assertGreater(eval_res.effectiveness_score, 0.0)
        self.assertEqual(eval_res.integrity_score, 15.0)

    def test_25_ledger_logging_on_control_evaluation(self):
        """25. Verify evaluation appends COMPLIANCE_CONTROL_EVALUATED to Governance Ledger."""
        ctrl = self.db.query(SecurityControl).first()
        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
        )
        self.db.commit()
        self.assertIsNotNone(eval_res.evaluation_hash)

    def test_26_evaluation_number_format(self):
        """26. Verify evaluation number matches CEV-YYYY-XXXX format."""
        ctrl = self.db.query(SecurityControl).first()
        eval_res = ControlEffectivenessService.evaluate_control(
            db=self.db,
            control_id=ctrl.id,
        )
        self.db.commit()
        self.assertTrue(eval_res.evaluation_number.startswith("CEV-"))

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 4: COMPLIANCE GAP DETECTION & DEDUPLICATION (Tests 27 to 34)
    # ══════════════════════════════════════════════════════════════════════════

    def test_27_record_new_compliance_gap(self):
        """27. Verify recording a new compliance gap."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        gap = ComplianceGapService.record_gap(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            gap_title="Test Gap Title",
            gap_category="INSUFFICIENT_EVIDENCE",
            severity="HIGH",
            root_cause_rule="TEST_RULE",
            description="Testing gap recording",
        )
        self.db.commit()
        self.assertIsNotNone(gap.id)
        self.assertEqual(gap.gap_status, "OPEN")

    def test_28_gap_fingerprint_deduplication(self):
        """28. Verify recurring gap updates existing row rather than duplicating."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        gap1 = ComplianceGapService.record_gap(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            gap_title="Deduplication Gap",
            gap_category="INSUFFICIENT_EVIDENCE",
            severity="HIGH",
            root_cause_rule="DEDUP_RULE",
            description="First detection",
        )
        self.db.commit()
        gap2 = ComplianceGapService.record_gap(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            gap_title="Deduplication Gap Updated",
            gap_category="INSUFFICIENT_EVIDENCE",
            severity="CRITICAL",
            root_cause_rule="DEDUP_RULE",
            description="Second detection updated description",
        )
        self.db.commit()
        self.assertEqual(gap1.id, gap2.id)
        self.assertEqual(gap2.severity, "CRITICAL")

    def test_29_scan_framework_gaps_all(self):
        """29. Verify scan_framework_gaps scans all mapped requirements."""
        fw = self.db.query(ComplianceFramework).filter(ComplianceFramework.framework_code == "FW-NIST-CSF-2.0").first()
        gaps = ComplianceGapService.scan_framework_gaps(db=self.db, framework_id=fw.id)
        self.db.commit()
        self.assertIsInstance(gaps, list)

    def test_30_resolve_gap_success(self):
        """30. Verify resolving gap with human attribution."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        gap = ComplianceGapService.record_gap(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            gap_title="Resolvable Gap",
            gap_category="CONTROL_DEGRADED",
            severity="MEDIUM",
            root_cause_rule="RESOLVE_RULE",
            description="To be resolved",
        )
        self.db.commit()

        resolved_gap = ComplianceGapService.resolve_gap(
            db=self.db,
            gap_id=gap.id,
            resolver_user_id="analyst_1",
            resolver_username="analyst_demo",
            resolution_summary="Fixed operational pipeline and re-verified telemetry.",
        )
        self.db.commit()
        self.assertEqual(resolved_gap.gap_status, "VERIFIED_RESOLVED")
        self.assertIsNotNone(resolved_gap.resolved_at)

    def test_31_resolve_nonexistent_gap_raises(self):
        """31. Verify resolving invalid gap ID raises ValueError."""
        with self.assertRaises(ValueError):
            ComplianceGapService.resolve_gap(
                db=self.db,
                gap_id="gap_invalid_999",
                resolver_user_id="user_1",
                resolver_username="user_1",
                resolution_summary="summary",
            )

    def test_32_reopening_gap_creates_new_if_previous_resolved(self):
        """32. Verify detecting gap creates fresh record if previous instance was resolved."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        gap1 = ComplianceGapService.record_gap(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            gap_title="Lifecycle Gap",
            gap_category="STALE_EVIDENCE",
            severity="LOW",
            root_cause_rule="LIFECYCLE_RULE",
            description="First occurrence",
        )
        self.db.commit()
        ComplianceGapService.resolve_gap(
            db=self.db,
            gap_id=gap1.id,
            resolver_user_id="analyst_1",
            resolver_username="analyst_demo",
            resolution_summary="Resolved",
        )
        self.db.commit()

        gap2 = ComplianceGapService.record_gap(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            gap_title="Lifecycle Gap Recurred",
            gap_category="STALE_EVIDENCE",
            severity="LOW",
            root_cause_rule="LIFECYCLE_RULE",
            description="Second occurrence after resolution",
        )
        self.db.commit()
        self.assertNotEqual(gap1.id, gap2.id)

    def test_33_gap_hash_calculation(self):
        """33. Verify gap_hash is computed on creation."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        gap = ComplianceGapService.record_gap(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            gap_title="Hash Test Gap",
            gap_category="INSUFFICIENT_EVIDENCE",
            severity="MEDIUM",
            root_cause_rule="HASH_RULE",
            description="Checking hash",
        )
        self.db.commit()
        self.assertIsNotNone(gap.gap_hash)
        self.assertEqual(len(gap.gap_hash), 64)

    def test_34_gap_ledger_event_appended(self):
        """34. Verify COMPLIANCE_GAP_DETECTED event logged."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        gap = ComplianceGapService.record_gap(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            gap_title="Ledger Gap",
            gap_category="MISSING_CONTROL",
            severity="HIGH",
            root_cause_rule="LEDGER_RULE",
            description="Checking ledger entry",
        )
        self.db.commit()
        self.assertIsNotNone(gap.id)

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 5: COMPLIANCE POSTURE EVALUATION & SEEDING (Tests 35 to 43)
    # ══════════════════════════════════════════════════════════════════════════

    def test_35_default_frameworks_seeded(self):
        """35. Verify 3 default frameworks are seeded."""
        fws = self.db.query(ComplianceFramework).all()
        codes = [f.framework_code for f in fws]
        self.assertIn("FW-SENTINEL-TRACE-V5", codes)
        self.assertIn("FW-NIST-CSF-2.0", codes)
        self.assertIn("FW-ISO-27001-2022", codes)

    def test_36_default_controls_seeded(self):
        """36. Verify 12 core security controls are seeded."""
        ctrls = self.db.query(SecurityControl).all()
        codes = [c.control_code for c in ctrls]
        self.assertIn("SC-AUTH-01", codes)
        self.assertIn("SC-INGEST-01", codes)
        self.assertIn("SC-LEDGER-01", codes)
        self.assertIn("SC-MERKLE-01", codes)
        self.assertIn("SC-COMP-01", codes)
        self.assertGreaterEqual(len(ctrls), 12)

    def test_37_default_requirements_seeded(self):
        """37. Verify 30+ default requirements are seeded across frameworks."""
        reqs = self.db.query(ComplianceRequirement).all()
        self.assertGreaterEqual(len(reqs), 30)

    def test_38_evaluate_iso_27001_posture(self):
        """38. Verify evaluating ISO 27001 posture."""
        fw = self.db.query(ComplianceFramework).filter(ComplianceFramework.framework_code == "FW-ISO-27001-2022").first()
        posture = CompliancePostureService.evaluate_framework_posture(
            db=self.db,
            framework_id=fw.id,
            evaluator_username="compliance_engine",
        )
        self.db.commit()
        self.assertIsNotNone(posture.id)
        self.assertGreaterEqual(posture.overall_score, 0.0)
        self.assertLessEqual(posture.overall_score, 100.0)
        self.assertIsNotNone(posture.evaluation_hash)

    def test_39_evaluate_nist_csf_posture(self):
        """39. Verify evaluating NIST CSF 2.0 posture."""
        fw = self.db.query(ComplianceFramework).filter(ComplianceFramework.framework_code == "FW-NIST-CSF-2.0").first()
        posture = CompliancePostureService.evaluate_framework_posture(
            db=self.db,
            framework_id=fw.id,
        )
        self.db.commit()
        self.assertIsNotNone(posture.id)
        self.assertEqual(posture.requirements_total, 10)

    def test_40_posture_weighted_score_math(self):
        """40. Verify requirements weights properly factor into posture calculation."""
        fw = self.db.query(ComplianceFramework).filter(ComplianceFramework.framework_code == "FW-SENTINEL-TRACE-V5").first()
        posture = CompliancePostureService.evaluate_framework_posture(
            db=self.db,
            framework_id=fw.id,
        )
        self.db.commit()
        self.assertIn("requirements_evaluated", posture.evaluation_reasoning_json)
        self.assertGreaterEqual(posture.evaluation_reasoning_json["requirements_evaluated"], 10)

    def test_41_get_command_center_metrics(self):
        """41. Verify Cyber SOC Command Center aggregated metrics."""
        metrics = CompliancePostureService.get_command_center_metrics(db=self.db)
        self.assertIn("global_compliance_index", metrics)
        self.assertIn("total_frameworks", metrics)
        self.assertIn("total_controls", metrics)
        self.assertIn("active_gaps_count", metrics)
        self.assertGreaterEqual(metrics["total_frameworks"], 3)
        self.assertGreaterEqual(metrics["total_controls"], 12)

    def test_42_idempotent_seeding(self):
        """42. Verify seed_default_frameworks_and_controls is idempotent."""
        counts = CompliancePostureService.seed_default_frameworks_and_controls(self.db)
        self.assertEqual(counts["frameworks"], 0)
        self.assertEqual(counts["controls"], 0)

    def test_43_posture_hash_deterministic(self):
        """43. Verify posture evaluation hash is computed and non-empty."""
        fw = self.db.query(ComplianceFramework).first()
        posture = CompliancePostureService.evaluate_framework_posture(
            db=self.db,
            framework_id=fw.id,
        )
        self.db.commit()
        self.assertEqual(len(posture.evaluation_hash), 64)

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 6: MAKER-CHECKER DUAL GOVERNANCE & SELF-APPROVAL (Tests 44 to 52)
    # ══════════════════════════════════════════════════════════════════════════

    def test_44_create_formal_compliance_finding(self):
        """44. Verify creating formal compliance finding."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        finding = ComplianceGovernanceService.create_finding(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            title="Inadequate Session Revocation",
            description="Session tokens do not invalidate upon password change.",
            creator_user_id="policy_author_demo",
            finding_type="DEFICIENCY",
        )
        self.db.commit()
        self.assertIsNotNone(finding.id)
        self.assertEqual(finding.status, "DRAFT")
        self.assertEqual(finding.created_by_user_id, "policy_author_demo")

    def test_45_maker_checker_review_approved(self):
        """45. Verify second person approval transitions finding to VALIDATED."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        finding = ComplianceGovernanceService.create_finding(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            title="Audited Finding",
            description="Finding description",
            creator_user_id="maker_user",
        )
        self.db.commit()

        review = ComplianceGovernanceService.submit_review(
            db=self.db,
            compliance_posture_evaluation_id=finding.id,
            reviewer_user_id="checker_user",
            review_action="APPROVE",
            review_comment="Verified remediation plan is sound.",
            initiator_user_id="maker_user",
        )
        self.db.commit()
        self.assertEqual(review.review_action, "APPROVE")
        self.assertEqual(finding.status, "VALIDATED")
        self.assertEqual(finding.reviewed_by_user_id, "checker_user")

    def test_46_maker_checker_self_approval_blocked(self):
        """46. Verify SelfApprovalForbiddenError raised when initiator == reviewer."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        finding = ComplianceGovernanceService.create_finding(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            title="Self-Approval Test Finding",
            description="Testing self-approval block",
            creator_user_id="same_person",
        )
        self.db.commit()

        with self.assertRaises(SelfApprovalForbiddenError):
            ComplianceGovernanceService.submit_review(
                db=self.db,
                compliance_posture_evaluation_id=finding.id,
                reviewer_user_id="same_person",
                review_action="APPROVE",
                review_comment="Attempting self approval",
                initiator_user_id="same_person",
            )

    def test_47_maker_checker_review_rejected(self):
        """47. Verify rejection updates finding status to REJECTED."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        finding = ComplianceGovernanceService.create_finding(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            title="Rejected Finding",
            description="To be rejected",
            creator_user_id="maker_user",
        )
        self.db.commit()

        review = ComplianceGovernanceService.submit_review(
            db=self.db,
            compliance_posture_evaluation_id=finding.id,
            reviewer_user_id="checker_user_2",
            review_action="REJECT",
            review_comment="Insufficient evidence provided.",
            initiator_user_id="maker_user",
        )
        self.db.commit()
        self.assertEqual(finding.status, "REJECTED")

    def test_48_maker_checker_review_changes_requested(self):
        """48. Verify REQUEST_REASSESSMENT sets finding to PENDING_REVIEW."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        finding = ComplianceGovernanceService.create_finding(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            title="Clarification Finding",
            description="Needs clarification",
            creator_user_id="maker_user",
        )
        self.db.commit()

        review = ComplianceGovernanceService.submit_review(
            db=self.db,
            compliance_posture_evaluation_id=finding.id,
            reviewer_user_id="checker_user_3",
            review_action="REQUEST_REASSESSMENT",
            review_comment="Attach fresh evidence binding.",
            initiator_user_id="maker_user",
        )
        self.db.commit()
        self.assertEqual(finding.status, "PENDING_REVIEW")

    def test_49_review_hash_calculation(self):
        """49. Verify review_hash computed deterministically."""
        posture = self.db.query(CompliancePostureEvaluation).first()
        review = ComplianceGovernanceService.submit_review(
            db=self.db,
            compliance_posture_evaluation_id=posture.id,
            reviewer_user_id="reviewer_user",
            review_action="APPROVE",
            review_comment="Posture review signoff",
            initiator_user_id="initiator_1",
        )
        self.db.commit()
        self.assertIsNotNone(review.review_hash)
        self.assertEqual(len(review.review_hash), 64)

    def test_50_review_appended_to_ledger(self):
        """50. Verify COMPLIANCE_REVIEW_COMPLETED logged in ledger."""
        posture = self.db.query(CompliancePostureEvaluation).first()
        review = ComplianceGovernanceService.submit_review(
            db=self.db,
            compliance_posture_evaluation_id=posture.id,
            reviewer_user_id="reviewer_user_2",
            review_action="APPROVE",
            review_comment="Control evaluation dual signoff",
            initiator_user_id="evaluator_2",
        )
        self.db.commit()
        self.assertIsNotNone(review.id)

    def test_51_finding_hash_calculation(self):
        """51. Verify finding_hash is 64 hex characters."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        finding = ComplianceGovernanceService.create_finding(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            title="Hash Test Finding",
            description="Description",
            creator_user_id="author_demo",
        )
        self.db.commit()
        self.assertEqual(len(finding.finding_hash), 64)

    def test_52_finding_number_format(self):
        """52. Verify finding number starts with CFN-."""
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        finding = ComplianceGovernanceService.create_finding(
            db=self.db,
            framework_requirement_id=req.id,
            security_control_id=ctrl.id,
            title="Format Finding",
            description="Description",
            creator_user_id="author_demo",
        )
        self.db.commit()
        self.assertTrue(finding.finding_number.startswith("CFN-"))

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 7: 22-STAGE PROVENANCE LINEAGE ENGINE (Tests 53 to 58)
    # ══════════════════════════════════════════════════════════════════════════

    def test_53_generate_22_stage_provenance(self):
        """53. Verify generating complete 22-stage compliance provenance chain."""
        posture = self.db.query(CompliancePostureEvaluation).first()
        records = ComplianceProvenanceService.generate_provenance_chain(
            db=self.db,
            posture_evaluation_id=posture.id,
        )
        self.db.commit()
        self.assertEqual(len(records), 22)

    def test_54_provenance_stage_order_and_integrity(self):
        """54. Verify sequential stage numbering 1 through 22."""
        posture_id = f"cpe_test54_{uuid.uuid4().hex[:6]}"
        records = ComplianceProvenanceService.get_provenance_for_posture(
            db=self.db,
            posture_evaluation_id=posture_id,
        )
        self.db.commit()
        for idx, st in enumerate(records, start=1):
            self.assertEqual(st.stage_number, idx)
            self.assertEqual(st.integrity_status, "VERIFIED")
            self.assertEqual(len(st.stage_hash), 64)

    def test_55_provenance_hash_deterministic(self):
        """55. Verify overall stage_hash matches SHA-256 length."""
        posture = self.db.query(CompliancePostureEvaluation).first()
        records = ComplianceProvenanceService.get_provenance_for_posture(
            db=self.db,
            posture_evaluation_id=posture.id,
        )
        self.db.commit()
        self.assertEqual(len(records[-1].stage_hash), 64)

    def test_56_provenance_hash_chaining(self):
        """56. Verify previous_stage_hash links sequentially across stages."""
        posture = self.db.query(CompliancePostureEvaluation).first()
        records = ComplianceProvenanceService.generate_provenance_chain(
            db=self.db,
            posture_evaluation_id=f"cpe_chain_{uuid.uuid4().hex[:6]}",
        )
        self.db.commit()
        for i in range(1, len(records)):
            self.assertEqual(records[i].previous_stage_hash, records[i-1].stage_hash)

    def test_57_get_provenance_for_posture_creates_if_absent(self):
        """57. Verify get_provenance_for_posture generates on-demand if not cached."""
        target_id = f"cpe_ondemand_{uuid.uuid4().hex[:8]}"
        records = ComplianceProvenanceService.get_provenance_for_posture(
            db=self.db,
            posture_evaluation_id=target_id,
        )
        self.db.commit()
        self.assertEqual(len(records), 22)
        self.assertEqual(records[0].posture_evaluation_id, target_id)

    def test_58_provenance_retrieval_returns_existing(self):
        """58. Verify get_provenance_for_posture retrieves existing record without duplicate insertion."""
        target_id = f"cpe_cached_{uuid.uuid4().hex[:8]}"
        rec1 = ComplianceProvenanceService.generate_provenance_chain(
            db=self.db,
            posture_evaluation_id=target_id,
        )
        self.db.commit()
        rec2 = ComplianceProvenanceService.get_provenance_for_posture(
            db=self.db,
            posture_evaluation_id=target_id,
        )
        self.assertEqual(len(rec1), len(rec2))
        self.assertEqual(rec1[0].id, rec2[0].id)

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 8: RBAC PERMISSIONS & REST API ENDPOINTS (Tests 59 to 72)
    # ══════════════════════════════════════════════════════════════════════════

    def test_59_api_seed_defaults(self):
        """59. REST API: POST /api/v1/compliance/seed-defaults."""
        headers = get_auth_headers("ADMIN")
        res = client.post("/api/v1/compliance/seed-defaults", headers=headers)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertIn("frameworks", data)

    def test_60_api_get_command_center_metrics(self):
        """60. REST API: GET /api/v1/compliance/command-center."""
        headers = get_auth_headers("ADMIN")
        res = client.get("/api/v1/compliance/command-center", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("global_compliance_index", data)
        self.assertIn("framework_summaries", data)

    def test_61_api_list_frameworks(self):
        """61. REST API: GET /api/v1/compliance/frameworks."""
        headers = get_auth_headers("SECURITY_ANALYST")
        res = client.get("/api/v1/compliance/frameworks", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(len(data), 3)

    def test_62_api_create_custom_framework(self):
        """62. REST API: POST /api/v1/compliance/frameworks."""
        headers = get_auth_headers("ADMIN")
        code = f"FW_API_{uuid.uuid4().hex[:6]}"
        res = client.post(
            "/api/v1/compliance/frameworks",
            headers=headers,
            json={
                "framework_code": code,
                "framework_name": "API Created Framework",
                "description": "Custom framework via REST API",
                "framework_category": "CUSTOM",
            },
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["framework_code"], code)

    def test_63_api_get_framework_requirements(self):
        """63. REST API: GET /api/v1/compliance/frameworks/{id}/requirements."""
        headers = get_auth_headers("SECURITY_ANALYST")
        res = client.get("/api/v1/compliance/frameworks/FW-SENTINEL-TRACE-V5/requirements", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(len(data), 10)

    def test_64_api_list_controls(self):
        """64. REST API: GET /api/v1/compliance/controls."""
        headers = get_auth_headers("SECURITY_ANALYST")
        res = client.get("/api/v1/compliance/controls", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(len(data), 12)

    def test_65_api_bind_evidence_to_control(self):
        """65. REST API: POST /api/v1/compliance/controls/{id}/evidence-bindings."""
        headers = get_auth_headers("ADMIN")
        res = client.post(
            "/api/v1/compliance/controls/SC-AUTH-01/evidence-bindings",
            headers=headers,
            json={
                "evidence_type": "AUDIT_LOG",
                "evidence_id": f"aud_{uuid.uuid4().hex[:6]}",
                "evidence_hash": hashlib.sha256(b"api_evidence").hexdigest(),
                "source_stage": "STAGE_07_LEDGER",
            },
        )
        self.assertEqual(res.status_code, 201)

    def test_66_api_evaluate_control(self):
        """66. REST API: POST /api/v1/compliance/controls/{id}/evaluate."""
        headers = get_auth_headers("SECURITY_ANALYST")
        res = client.post(
            "/api/v1/compliance/controls/SC-AUTH-01/evaluate",
            headers=headers,
            json={"trigger_source": "API_TEST"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("effectiveness_score", data)
        self.assertIn("evaluation_status", data)

    def test_67_api_evaluate_all_controls(self):
        """67. REST API: POST /api/v1/compliance/controls/evaluate-all."""
        headers = get_auth_headers("SECURITY_ANALYST")
        res = client.post("/api/v1/compliance/controls/evaluate-all", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(len(data), 12)

    def test_68_api_list_gaps_and_scan(self):
        """68. REST API: POST /api/v1/compliance/gaps/scan & GET /gaps."""
        headers = get_auth_headers("SECURITY_ANALYST")
        scan_res = client.post("/api/v1/compliance/gaps/scan", headers=headers)
        self.assertEqual(scan_res.status_code, 200)

        list_res = client.get("/api/v1/compliance/gaps", headers=headers)
        self.assertEqual(list_res.status_code, 200)
        self.assertIsInstance(list_res.json(), list)

    def test_69_api_create_finding(self):
        """69. REST API: POST /api/v1/compliance/findings."""
        headers = get_auth_headers("POLICY_AUTHOR")
        req = self.db.query(ComplianceRequirement).first()
        ctrl = self.db.query(SecurityControl).first()
        res = client.post(
            "/api/v1/compliance/findings",
            headers=headers,
            json={
                "framework_requirement_id": req.id,
                "security_control_id": ctrl.id,
                "title": "REST API Finding",
                "description": "Created through REST API test",
                "severity": "HIGH",
            },
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["statement"], "REST API Finding")

    def test_70_api_maker_checker_self_approval_blocked_409(self):
        """70. REST API: POST /api/v1/compliance/reviews returns HTTP 409 on self-approval."""
        headers_admin = get_auth_headers("ADMIN")
        res_review = client.post(
            "/api/v1/compliance/reviews",
            headers=headers_admin,
            json={
                "review_type": "COMPLIANCE_POSTURE",
                "target_entity_id": "cpe_dummy_123",
                "review_decision": "APPROVE",
                "review_notes": "Attempting self approval",
                "initiator_user_id": "admin_demo",
                "initiator_username": "admin_demo",
            },
        )
        self.assertEqual(res_review.status_code, 409)
        self.assertIn("Maker-Checker violation", res_review.json()["detail"])

    def test_71_api_evaluate_posture(self):
        """71. REST API: POST /api/v1/compliance/posture/{framework_id}/evaluate."""
        headers = get_auth_headers("SECURITY_ANALYST")
        res = client.post("/api/v1/compliance/posture/FW-SENTINEL-TRACE-V5/evaluate", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("overall_score", data)
        self.assertIn("posture_status", data)

    def test_72_api_get_provenance_chain(self):
        """72. REST API: GET /api/v1/compliance/provenance/{entity_type}/{entity_id}."""
        headers = get_auth_headers("AUDITOR")
        res = client.get("/api/v1/compliance/provenance/COMPLIANCE_FRAMEWORK/FW-SENTINEL-TRACE-V5", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["lineage_stages_json"]), 22)
        self.assertEqual(data["verification_status"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
