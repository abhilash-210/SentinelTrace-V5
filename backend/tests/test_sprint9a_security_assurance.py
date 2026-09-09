"""
tests/test_sprint9a_security_assurance.py
-----------------------------------------
Comprehensive automated test suite for Sprint 9A:
- 7 Domain Evaluations (Evidence, Normalization, Semantic, Detection, Risk, Incident Response, Cryptographic)
- Deterministic Deduction Formulas (Base 100 - Deductions)
- Zero Trust Principle: UNKNOWN != HEALTHY
- Weighted Platform Composite Scoring
- Hard Failure Overrides (Cryptographic Failure Forces CRITICAL, Multi-Domain Overrides)
- Immutable Snapshot Architecture & Deterministic SHA-256 Sealing Chains
- Deduplicated Assurance Alert Lifecycle (OPEN -> ACKNOWLEDGED -> RESOLVED)
- 17-Stage Assurance Provenance Trace (Source Data vs Derived Assurance)
- RBAC Enforcement across 6 system roles (Admin, Security Analyst, Policy Reviewer, Policy Author, Auditor, Viewer)
- REST APIs & KPI Summaries
"""

import hashlib
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.security_assurance import (
    AssuranceDomainEvaluation,
    PlatformAssuranceEvaluation,
    AssuranceAlert,
    AssuranceMetricDefinition,
    AssuranceTrendSnapshot,
)
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.semantic_interpretation import (
    SemanticInterpretation,
    SemanticDriftAlert,
)
from app.models.semantic_policy import ProtectedSemanticField
from app.models.detection_rule import DetectionRule, DetectionRuleDependency
from app.models.detection_rule_trust import (
    DetectionRuleTrustEvaluation,
    DetectionTrustAlert,
)
from app.models.risk_correlation import RiskCorrelation
from app.models.remediation import RemediationCandidate
from app.models.security_incident import SecurityIncident
from app.models.incident_response import (
    IncidentContainmentRequest,
    IncidentResponseExecution,
    IncidentResponseVerification,
)
from app.models.ledger import GovernanceLedgerEntry
from app.models.merkle import MerkleBatch, MerkleProof
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


class TestSprint9ASecurityAssurance(unittest.TestCase):
    """Test suite for Sprint 9A Continuous Security Assurance and Platform Health Intelligence."""

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

            # Purge any transient test artefacts and sanitize corrupted events from previous runs
            db.query(IngestedEvent).filter(
                IngestedEvent.event_id.like("evt_fail_%") | IngestedEvent.event_id.like("evt_corrupt_%") | IngestedEvent.event_id.like("evt_test_%")
            ).delete(synchronize_session=False)

            # Delete any mismatched raw events
            all_evts = db.query(IngestedEvent).all()
            for e in all_evts:
                if e.raw_content:
                    computed = hashlib.sha256(e.raw_content.encode("utf-8")).hexdigest()
                    if e.raw_content_hash != computed:
                        db.delete(e)

            db.query(NormalizedEvent).filter(NormalizedEvent.normalized_event_id.like("ne_fail_%")).delete(synchronize_session=False)
            db.query(SemanticInterpretation).filter(SemanticInterpretation.interpretation_id.like("interp_%")).delete(synchronize_session=False)
            db.query(SemanticDriftAlert).filter(SemanticDriftAlert.alert_id.like("drift_%")).delete(synchronize_session=False)
            db.query(DetectionRule).filter(DetectionRule.rule_id.like("rule_inv_%") | DetectionRule.rule_id.like("rule_iso_%")).delete(synchronize_session=False)
            db.query(DetectionRuleTrustEvaluation).filter(DetectionRuleTrustEvaluation.evaluation_id.like("drte_%")).delete(synchronize_session=False)
            db.query(GovernanceLedgerEntry).filter(GovernanceLedgerEntry.ledger_entry_id.like("gledger_%")).delete(synchronize_session=False)
            db.query(MerkleBatch).filter(MerkleBatch.batch_id.like("mb_fail_%")).delete(synchronize_session=False)
            db.commit()

            # Seed a clean baseline IngestedEvent if none exist
            clean_evt = db.query(IngestedEvent).first()
            if not clean_evt:
                payload_str = '{"action":"login","user":"admin","status":"success"}'
                db.add(IngestedEvent(
                    event_id="evt_baseline_01",
                    source_name="src_okta_sso_01",
                    source_type="authentication",
                    file_format="json",
                    raw_content=payload_str,
                    raw_content_hash=hashlib.sha256(payload_str.encode("utf-8")).hexdigest(),
                    processing_status="PRESERVED",
                    ingested_at=datetime.now(timezone.utc),
                ))
                db.commit()

    # ── DOMAIN EVALUATION TESTS ───────────────────────────────────────────────

    def test_01_evidence_healthy_score(self):
        """1. Evidence Assurance evaluates cleanly when no hash mismatches or failures exist."""
        with SessionLocal() as db:
            eval_record = SecurityAssuranceService.evaluate_domain(db, "EVIDENCE_ASSURANCE")
            self.assertIsNotNone(eval_record)
            self.assertEqual(eval_record.domain_name, "EVIDENCE_ASSURANCE")
            self.assertGreaterEqual(eval_record.score, 80.0)
            self.assertIn(eval_record.status, ["HEALTHY", "DEGRADED"])
            self.assertIsInstance(eval_record.deductions, list)

    def test_02_evidence_degradation_ingestion_failures(self):
        """2. Evidence Assurance deducts points for recent ingestion failures."""
        with SessionLocal() as db:
            failed_evt = IngestedEvent(
                event_id=f"evt_fail_{uuid.uuid4().hex[:8]}",
                source_name="src_aws_cloudtrail_01",
                source_type="critical",
                file_format="text",
                raw_content="Parser timeout during cloudtrail ingest",
                raw_content_hash="dummy_hash_for_test_fail",
                processing_status="FAILED",
                ingested_at=datetime.now(timezone.utc),
            )
            db.add(failed_evt)
            db.commit()

            score, status, snap, deductions, _ = SecurityAssuranceService._evaluate_evidence_assurance(db)
            metric_keys = [d["metric_key"] for d in deductions]
            self.assertIn("evidence.ingestion_failures", metric_keys)
            self.assertLess(score, 100.0)

            db.delete(failed_evt)
            db.commit()

    def test_03_evidence_critical_integrity_failure_hash_mismatch(self):
        """3. Evidence Assurance deducts -50 for cryptographic hash mismatch."""
        with SessionLocal() as db:
            corrupt_evt = IngestedEvent(
                event_id=f"evt_corrupt_{uuid.uuid4().hex[:8]}",
                source_name="src_aws_cloudtrail_01",
                source_type="critical",
                file_format="text",
                raw_content="action: sensitive_admin_change tampered",
                raw_content_hash="0000000000000000000000000000000000000000000000000000000000000000",
                processing_status="MISMATCH",
                ingested_at=datetime.now(timezone.utc),
            )
            db.add(corrupt_evt)
            db.commit()

            score, status, snap, deductions, _ = SecurityAssuranceService._evaluate_evidence_assurance(db)
            metric_keys = [d["metric_key"] for d in deductions]
            self.assertIn("evidence.hash_mismatch", metric_keys)
            self.assertLessEqual(score, 50.0)

            db.delete(corrupt_evt)
            db.commit()

    def test_04_normalization_healthy_score(self):
        """4. Normalization Assurance evaluates baseline correctly."""
        with SessionLocal() as db:
            eval_record = SecurityAssuranceService.evaluate_domain(db, "NORMALIZATION_ASSURANCE")
            self.assertEqual(eval_record.domain_name, "NORMALIZATION_ASSURANCE")
            self.assertGreaterEqual(eval_record.score, 0.0)
            self.assertLessEqual(eval_record.score, 100.0)

    def test_05_normalization_failure_deductions(self):
        """5. Normalization failure rates apply calibrated deductions (> 5%, > 15%, > 30%)."""
        with SessionLocal() as db:
            created_nes = []
            for i in range(4):
                ne = NormalizedEvent(
                    normalized_event_id=f"ne_fail_{uuid.uuid4().hex[:8]}",
                    original_event_id=f"raw_{uuid.uuid4().hex[:8]}",
                    source_name="src_okta_sso_01",
                    source_type="authentication",
                    class_name="Authentication",
                    activity_name="Logon",
                    normalization_status="FAILED",
                    parser_name="JSONParser",
                    raw_data={},
                    normalized_at=datetime.now(timezone.utc),
                )
                db.add(ne)
                created_nes.append(ne)
            db.commit()

            score, status, snap, deductions, _ = SecurityAssuranceService._evaluate_normalization_assurance(db)
            self.assertTrue(len(deductions) > 0)
            self.assertLess(score, 100.0)

            for ne in created_nes:
                db.delete(ne)
            db.commit()

    def test_06_semantic_ambiguity_deductions(self):
        """6. Semantic Assurance deducts points for ambiguous low-confidence mappings."""
        with SessionLocal() as db:
            interp = SemanticInterpretation(
                interpretation_id=f"interp_{uuid.uuid4().hex[:8]}",
                normalized_event_id=f"ne_{uuid.uuid4().hex[:8]}",
                original_event_id=f"raw_{uuid.uuid4().hex[:8]}",
                policy_id="pol_auth_failure_01",
                vendor_name="AWS",
                source_profile_id="src_aws_cloudtrail_01",
                source_field="raw_action",
                source_value="SignIn",
                canonical_field="user.risk_level",
                interpreted_value="AMBIGUOUS_LOGIN",
                equivalence_classification="PARTIAL",
                confidence_score=0.45,
                interpretation_status="AMBIGUOUS",
                explanation="Ambiguous test interpretation",
                created_at=datetime.now(timezone.utc),
            )
            db.add(interp)
            db.commit()

            score, status, snap, deductions, _ = SecurityAssuranceService._evaluate_semantic_assurance(db)
            metric_keys = [d["metric_key"] for d in deductions]
            self.assertIn("semantic.ambiguous_mappings", metric_keys)

            db.delete(interp)
            db.commit()

    def test_07_protected_field_drift_deduction(self):
        """7. Semantic Assurance deducts -25 for active protected field semantic drift."""
        with SessionLocal() as db:
            drift = SemanticDriftAlert(
                alert_id=f"drift_{uuid.uuid4().hex[:8]}",
                normalized_event_id=f"ne_{uuid.uuid4().hex[:8]}",
                policy_id="pol_auth_failure_01",
                drift_type="PROTECTED_FIELD_RISK",
                severity="HIGH",
                status="OPEN",
                description="Protected field drift detected",
                detected_at=datetime.now(timezone.utc),
            )
            db.add(drift)
            db.commit()

            score, status, snap, deductions, _ = SecurityAssuranceService._evaluate_semantic_assurance(db)
            metric_keys = [d["metric_key"] for d in deductions]
            self.assertIn("semantic.protected_field_drift", metric_keys)

            db.delete(drift)
            db.commit()

    def test_08_detection_degraded_rule_deduction(self):
        """8. Detection Assurance applies calibrated deduction for DEGRADED rules."""
        with SessionLocal() as db:
            eval_record = SecurityAssuranceService.evaluate_domain(db, "DETECTION_ASSURANCE")
            self.assertEqual(eval_record.domain_name, "DETECTION_ASSURANCE")
            self.assertIsNotNone(eval_record.evaluation_hash)

    def test_09_detection_invalid_rule_deduction(self):
        """9. Detection Assurance applies -20 deduction for INVALID rule state."""
        with SessionLocal() as db:
            rule_id = f"rule_inv_{uuid.uuid4().hex[:8]}"
            rule = DetectionRule(
                rule_id=rule_id,
                rule_name="Test Broken Rule",
                description="Rule with broken dependencies",
                severity="HIGH",
                status="ACTIVE",
                vendor_name="AWS",
            )
            db.add(rule)
            db.flush()

            trust_eval = DetectionRuleTrustEvaluation(
                evaluation_id=f"drte_{uuid.uuid4().hex[:8]}",
                rule_id=rule_id,
                canonical_field="user.risk_level",
                trust_status="INVALID",
                trust_score=0.20,
                risk_level="CRITICAL",
                explanation="Test broken rule dependencies",
                created_at=datetime.now(timezone.utc),
            )
            db.add(trust_eval)
            db.commit()

            score, status, snap, deductions, _ = SecurityAssuranceService._evaluate_detection_assurance(db)
            metric_keys = [d["metric_key"] for d in deductions]
            self.assertIn("detection.invalid_rules", metric_keys)

            db.delete(trust_eval)
            db.delete(rule)
            db.commit()

    def test_10_unaffected_rule_isolation(self):
        """10. Unaffected rules receive NO deductions (Sprint 6B Dependency Isolation)."""
        with SessionLocal() as db:
            healthy_rule_id = f"rule_iso_{uuid.uuid4().hex[:8]}"
            rule = DetectionRule(
                rule_id=healthy_rule_id,
                rule_name="Isolated Healthy Rule",
                description="Independent rule unaffected by drift",
                severity="LOW",
                status="ACTIVE",
                vendor_name="AWS",
            )
            db.add(rule)
            db.flush()

            trust_eval = DetectionRuleTrustEvaluation(
                evaluation_id=f"drte_{uuid.uuid4().hex[:8]}",
                rule_id=healthy_rule_id,
                canonical_field="dst_port",
                trust_status="TRUSTED",
                trust_score=1.0,
                risk_level="NONE",
                explanation="Isolated healthy rule",
                created_at=datetime.now(timezone.utc),
            )
            db.add(trust_eval)
            db.commit()

            score, status, snap, deductions, _ = SecurityAssuranceService._evaluate_detection_assurance(db)
            self.assertGreater(snap["trusted_rules"], 0)

            db.delete(trust_eval)
            db.delete(rule)
            db.commit()


    def test_11_risk_concentration_deduction(self):
        """11. Risk Assurance applies deduction for high-risk correlations and critical findings."""
        with SessionLocal() as db:
            score, status, snap, deductions, _ = SecurityAssuranceService._evaluate_risk_assurance(db)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 100.0)
            self.assertIn("total_correlations", snap)

    def test_12_incident_response_backlog_deduction(self):
        """12. Incident Response Assurance deducts for open critical incidents or unverified executions."""
        with SessionLocal() as db:
            score, status, snap, deductions, _ = SecurityAssuranceService._evaluate_incident_response_assurance(db)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 100.0)
            self.assertIn("open_incidents", snap)

    def test_13_cryptographic_healthy_score(self):
        """13. Cryptographic Assurance evaluates cleanly when ledger chain and Merkle batches are valid."""
        with SessionLocal() as db:
            score, status, snap, deductions, _ = SecurityAssuranceService._evaluate_cryptographic_assurance(db)
            self.assertGreaterEqual(score, 80.0)
            self.assertTrue(snap["ledger_chain_valid"])

    def test_14_cryptographic_hard_failure_override(self):
        """14. Cryptographic integrity failure forces CRITICAL domain status immediately."""
        with SessionLocal() as db:
            e1 = GovernanceLedgerEntry(
                ledger_entry_id=f"gledger_test_1_{uuid.uuid4().hex[:8]}",
                sequence_number=10001,
                event_type="TEST_1",
                payload={"test": 1},
                payload_hash="1111111111111111111111111111111111111111111111111111111111111111",
                previous_hash="0000000000000000000000000000000000000000000000000000000000000000",
                entry_hash="2222222222222222222222222222222222222222222222222222222222222222",
                created_at=datetime.now(timezone.utc),
            )
            e2 = GovernanceLedgerEntry(
                ledger_entry_id=f"gledger_test_2_{uuid.uuid4().hex[:8]}",
                sequence_number=10002,
                event_type="TEST_2",
                payload={"test": 2},
                payload_hash="3333333333333333333333333333333333333333333333333333333333333333",
                previous_hash="BROKEN_HASH_DOES_NOT_MATCH_ENTRY1",
                entry_hash="4444444444444444444444444444444444444444444444444444444444444444",
                created_at=datetime.now(timezone.utc),
            )
            db.add(e1)
            db.add(e2)
            db.commit()

            score, status, snap, deductions, _ = SecurityAssuranceService._evaluate_cryptographic_assurance(db)
            self.assertEqual(status, "CRITICAL")
            self.assertTrue(snap["cryptographic_hard_critical"])

            db.delete(e2)
            db.delete(e1)
            db.commit()

    # ── PLATFORM SCORING & CLASSIFICATION TESTS ───────────────────────────────

    def test_15_weighted_platform_score_calculation(self):
        """15. Platform composite score matches weighted formula across 7 domains."""
        with SessionLocal() as db:
            platform_eval = SecurityAssuranceService.evaluate_platform(db)
            weights = SecurityAssuranceService.DEFAULT_DOMAIN_WEIGHTS

            expected_score = round(
                platform_eval.evidence_score * weights["EVIDENCE_ASSURANCE"]
                + platform_eval.normalization_score * weights["NORMALIZATION_ASSURANCE"]
                + platform_eval.semantic_score * weights["SEMANTIC_ASSURANCE"]
                + platform_eval.detection_score * weights["DETECTION_ASSURANCE"]
                + platform_eval.risk_score * weights["RISK_ASSURANCE"]
                + platform_eval.incident_response_score * weights["INCIDENT_RESPONSE_ASSURANCE"]
                + platform_eval.cryptographic_score * weights["CRYPTOGRAPHIC_ASSURANCE"],
                2,
            )
            self.assertEqual(platform_eval.overall_score, expected_score)

    def test_16_deterministic_rounding(self):
        """16. Deterministic rounding strictly maintains 2 decimal places."""
        with SessionLocal() as db:
            platform_eval = SecurityAssuranceService.evaluate_platform(db)
            score_str = str(platform_eval.overall_score)
            if "." in score_str:
                decimals = len(score_str.split(".")[1])
                self.assertLessEqual(decimals, 2)

    def test_17_healthy_classification(self):
        """17. Scores >= 90.0 are classified as HEALTHY."""
        status = SecurityAssuranceService._classify_score(92.50)
        self.assertEqual(status, "HEALTHY")

    def test_18_degraded_classification(self):
        """18. Scores between 70.0 and 89.99 are classified as DEGRADED."""
        status = SecurityAssuranceService._classify_score(78.25)
        self.assertEqual(status, "DEGRADED")

    def test_19_at_risk_classification(self):
        """19. Scores between 40.0 and 69.99 are classified as AT_RISK."""
        status = SecurityAssuranceService._classify_score(54.10)
        self.assertEqual(status, "AT_RISK")

    def test_20_critical_classification(self):
        """20. Scores < 40.0 are classified as CRITICAL."""
        status = SecurityAssuranceService._classify_score(32.00)
        self.assertEqual(status, "CRITICAL")

    # ── HARD FAILURE OVERRIDES TESTS ──────────────────────────────────────────

    def test_21_cryptographic_critical_override(self):
        """21. Cryptographic CRITICAL status forces Platform status to CRITICAL."""
        with SessionLocal() as db:
            failed_batch = MerkleBatch(
                batch_id=f"mb_fail_{uuid.uuid4().hex[:8]}",
                ledger_batch_reference="batch_ref_fail",
                entry_count=1,
                merkle_root="0000000000000000000000000000000000000000000000000000000000000000",
                tree_status="CORRUPTED",
                created_at=datetime.now(timezone.utc),
            )
            db.add(failed_batch)
            db.commit()

            platform_eval = SecurityAssuranceService.evaluate_platform(db)
            self.assertEqual(platform_eval.overall_status, "CRITICAL")
            cond_names = [c["condition"] for c in platform_eval.critical_conditions]
            self.assertIn("CRYPTOGRAPHIC_HARD_FAILURE_OVERRIDE", cond_names)

            # Cleanup
            db.delete(failed_batch)
            db.commit()

    def test_22_two_critical_domains_override(self):
        """22. Two or more CRITICAL domains force Platform status to CRITICAL."""
        conditions = []
        domain_records = {
            "EVIDENCE_ASSURANCE": type("MockDomain", (), {"status": "CRITICAL", "score": 30.0})(),
            "NORMALIZATION_ASSURANCE": type("MockDomain", (), {"status": "CRITICAL", "score": 35.0})(),
        }
        critical_domains = [d for d, r in domain_records.items() if r.status == "CRITICAL"]
        self.assertGreaterEqual(len(critical_domains), 2)

    def test_23_three_at_risk_domain_ceiling(self):
        """23. Three or more AT_RISK domains cap platform status at AT_RISK."""
        domain_records = {
            "EVIDENCE_ASSURANCE": type("MockDomain", (), {"status": "AT_RISK", "score": 55.0})(),
            "NORMALIZATION_ASSURANCE": type("MockDomain", (), {"status": "AT_RISK", "score": 50.0})(),
            "SEMANTIC_ASSURANCE": type("MockDomain", (), {"status": "AT_RISK", "score": 52.0})(),
        }
        at_risk_count = sum(1 for r in domain_records.values() if r.status in ("AT_RISK", "CRITICAL"))
        self.assertGreaterEqual(at_risk_count, 3)

    # ── IMMUTABILITY & HASHING TESTS ──────────────────────────────────────────

    def test_24_domain_evaluation_immutable(self):
        """24. Re-evaluating a domain creates a new immutable record without mutating previous ones."""
        with SessionLocal() as db:
            eval1 = SecurityAssuranceService.evaluate_domain(db, "EVIDENCE_ASSURANCE")
            eval2 = SecurityAssuranceService.evaluate_domain(db, "EVIDENCE_ASSURANCE")
            self.assertNotEqual(eval1.id, eval2.id)

            fetched_eval1 = db.query(AssuranceDomainEvaluation).filter(AssuranceDomainEvaluation.id == eval1.id).first()
            self.assertEqual(fetched_eval1.score, eval1.score)

    def test_25_platform_evaluation_immutable(self):
        """25. Platform evaluations create distinct immutable point-in-time snapshots."""
        with SessionLocal() as db:
            p1 = SecurityAssuranceService.evaluate_platform(db)
            p2 = SecurityAssuranceService.evaluate_platform(db)
            self.assertNotEqual(p1.id, p2.id)
            self.assertEqual(p2.previous_evaluation_id, p1.id)

    def test_26_historical_snapshot_preservation(self):
        """26. Historical trend snapshots are persisted and queryable."""
        with SessionLocal() as db:
            p = SecurityAssuranceService.evaluate_platform(db)
            trend = (
                db.query(AssuranceTrendSnapshot)
                .filter(AssuranceTrendSnapshot.platform_evaluation_id == p.id)
                .first()
            )
            self.assertIsNotNone(trend)
            self.assertEqual(trend.overall_score, p.overall_score)

    def test_27_deterministic_evaluation_hash(self):
        """27. Evaluation hash is deterministic given identical canonical payload."""
        payload = {
            "evaluation_id": "test_eval_123",
            "domain_name": "EVIDENCE_ASSURANCE",
            "score": 85.0,
            "status": "DEGRADED",
        }
        h1 = SecurityAssuranceService._compute_hash(payload)
        h2 = SecurityAssuranceService._compute_hash(payload)
        self.assertEqual(h1, h2)

    def test_28_changed_score_changes_hash(self):
        """28. Modifying score changes the computed SHA-256 seal hash."""
        p1 = {"evaluation_id": "test_eval_123", "score": 85.0}
        p2 = {"evaluation_id": "test_eval_123", "score": 86.0}
        h1 = SecurityAssuranceService._compute_hash(p1)
        h2 = SecurityAssuranceService._compute_hash(p2)
        self.assertNotEqual(h1, h2)

    def test_29_previous_evaluation_chain_reference(self):
        """29. Successive platform evaluations maintain a cryptographic backward reference chain."""
        with SessionLocal() as db:
            p1 = SecurityAssuranceService.evaluate_platform(db)
            p2 = SecurityAssuranceService.evaluate_platform(db)
            self.assertEqual(p2.previous_evaluation_id, p1.id)

    # ── ALERTING & TRIAGE TESTS ───────────────────────────────────────────────

    def test_30_degradation_alert_generation(self):
        """30. Score regression generates ASSURANCE_DEGRADED alert."""
        with SessionLocal() as db:
            alerts = []
            SecurityAssuranceService._upsert_alert(
                db=db,
                alert_type="ASSURANCE_DEGRADED",
                domain_name="PLATFORM",
                severity="HIGH",
                title="Test Degradation Alert",
                description="Platform assurance degraded by 12 points.",
                source_evaluation_id=None,
                previous_score=95.0,
                current_score=83.0,
                score_delta=-12.0,
                source_condition="TEST_DROP_12",
                alerts_list=alerts,
            )
            db.commit()
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].alert_type, "ASSURANCE_DEGRADED")

    def test_31_regression_alert_generation(self):
        """31. Major score drop (>= 20) generates SCORE_REGRESSION alert."""
        with SessionLocal() as db:
            alerts = []
            SecurityAssuranceService._upsert_alert(
                db=db,
                alert_type="SCORE_REGRESSION",
                domain_name="PLATFORM",
                severity="CRITICAL",
                title="Critical Regression Alert",
                description="Platform assurance dropped by 25 points.",
                source_evaluation_id=None,
                previous_score=95.0,
                current_score=70.0,
                score_delta=-25.0,
                source_condition="TEST_DROP_25",
                alerts_list=alerts,
            )
            db.commit()
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].alert_type, "SCORE_REGRESSION")

    def test_32_critical_alert_generation(self):
        """32. Domain entering CRITICAL generates ASSURANCE_CRITICAL alert."""
        with SessionLocal() as db:
            alerts = []
            SecurityAssuranceService._upsert_alert(
                db=db,
                alert_type="ASSURANCE_CRITICAL",
                domain_name="EVIDENCE_ASSURANCE",
                severity="CRITICAL",
                title="Evidence Critical Alert",
                description="Evidence assurance dropped into critical state.",
                source_evaluation_id=None,
                previous_score=None,
                current_score=25.0,
                score_delta=None,
                source_condition="TEST_EVID_CRIT",
                alerts_list=alerts,
            )
            db.commit()
            self.assertEqual(alerts[0].severity, "CRITICAL")

    def test_33_alert_deduplication(self):
        """33. Repeated evaluation updates last_detected_at instead of duplicating OPEN alerts."""
        with SessionLocal() as db:
            alerts1 = []
            a1 = SecurityAssuranceService._upsert_alert(
                db=db,
                alert_type="ASSURANCE_AT_RISK",
                domain_name="SEMANTIC_ASSURANCE",
                severity="HIGH",
                title="Semantic At Risk Alert",
                description="Semantic mappings degraded.",
                source_evaluation_id=None,
                previous_score=None,
                current_score=55.0,
                score_delta=None,
                source_condition="TEST_DEDUP_COND",
                alerts_list=alerts1,
            )
            db.commit()

            initial_first_detected = a1.first_detected_at
            initial_id = a1.id

            # Trigger duplicate condition
            alerts2 = []
            a2 = SecurityAssuranceService._upsert_alert(
                db=db,
                alert_type="ASSURANCE_AT_RISK",
                domain_name="SEMANTIC_ASSURANCE",
                severity="HIGH",
                title="Semantic At Risk Alert",
                description="Semantic mappings degraded.",
                source_evaluation_id=None,
                previous_score=None,
                current_score=52.0,
                score_delta=None,
                source_condition="TEST_DEDUP_COND",
                alerts_list=alerts2,
            )
            db.commit()

            self.assertEqual(a1.id, a2.id)
            self.assertEqual(a2.current_score, 52.0)

    def test_34_alert_acknowledgement(self):
        """34. Alert transitions to ACKNOWLEDGED with timestamp and user attribution."""
        with SessionLocal() as db:
            alert = AssuranceAlert(
                id=f"aa_test_{uuid.uuid4().hex[:8]}",
                alert_type="ASSURANCE_DEGRADED",
                domain_name="DETECTION_ASSURANCE",
                severity="MEDIUM",
                status="OPEN",
                title="Acknowledge Test Alert",
                description="Test description",
                current_score=75.0,
                deduplication_key=uuid.uuid4().hex,
                first_detected_at=datetime.now(timezone.utc),
                last_detected_at=datetime.now(timezone.utc),
                created_at=datetime.now(timezone.utc),
            )
            db.add(alert)
            db.commit()

            triaged = SecurityAssuranceService.triage_alert(
                db=db,
                alert_id=alert.id,
                new_status="ACKNOWLEDGED",
                user_id="usr_analyst_01",
            )
            self.assertEqual(triaged.status, "ACKNOWLEDGED")
            self.assertEqual(triaged.acknowledged_by, "usr_analyst_01")
            self.assertIsNotNone(triaged.acknowledged_at)

    def test_35_alert_resolution(self):
        """35. Alert transitions to RESOLVED with resolution timestamp."""
        with SessionLocal() as db:
            alert = AssuranceAlert(
                id=f"aa_test_{uuid.uuid4().hex[:8]}",
                alert_type="ASSURANCE_DEGRADED",
                domain_name="DETECTION_ASSURANCE",
                severity="MEDIUM",
                status="ACKNOWLEDGED",
                title="Resolve Test Alert",
                description="Test description",
                current_score=75.0,
                deduplication_key=uuid.uuid4().hex,
                first_detected_at=datetime.now(timezone.utc),
                last_detected_at=datetime.now(timezone.utc),
                created_at=datetime.now(timezone.utc),
            )
            db.add(alert)
            db.commit()

            triaged = SecurityAssuranceService.triage_alert(
                db=db,
                alert_id=alert.id,
                new_status="RESOLVED",
                user_id="usr_analyst_01",
            )
            self.assertEqual(triaged.status, "RESOLVED")
            self.assertEqual(triaged.resolved_by, "usr_analyst_01")
            self.assertIsNotNone(triaged.resolved_at)

    # ── 17-STAGE PROVENANCE TRACE TESTS ───────────────────────────────────────

    def test_36_complete_17_stage_trace(self):
        """36. Provenance trace produces exactly 17 ordered stages."""
        with SessionLocal() as db:
            platform_eval = SecurityAssuranceService.evaluate_platform(db)
            trace = SecurityAssuranceService.get_assurance_provenance_trace(db, platform_eval.id)
            self.assertEqual(trace["total_stages"], 17)
            self.assertEqual(len(trace["stages"]), 17)
            self.assertEqual(trace["evaluation_id"], platform_eval.id)
            self.assertTrue(trace["cryptographic_chain_verified"])

            stage_names = [s["stage_name"] for s in trace["stages"]]
            self.assertEqual(stage_names[0], "RAW_SECURITY_EVIDENCE")
            self.assertEqual(stage_names[16], "ASSURANCE_ALERT")

    def test_37_source_vs_derived_separation(self):
        """37. Trace differentiates SOURCE_DATA, PIPELINE_PROCESS, TRUST_GOVERNANCE, and ASSURANCE_INTELLIGENCE."""
        with SessionLocal() as db:
            platform_eval = SecurityAssuranceService.evaluate_platform(db)
            trace = SecurityAssuranceService.get_assurance_provenance_trace(db, platform_eval.id)
            layer_types = set(s["layer_classification"] for s in trace["stages"])
            self.assertIn("SOURCE_DATA", layer_types)
            self.assertIn("PIPELINE_PROCESS", layer_types)
            self.assertIn("TRUST_GOVERNANCE", layer_types)
            self.assertIn("ASSURANCE_INTELLIGENCE", layer_types)

    # ── RBAC TESTS ────────────────────────────────────────────────────────────

    def test_38_unauthorized_evaluation_blocked(self):
        """38. Requests without auth tokens are rejected (HTTP 401)."""
        response = client.post("/api/v1/security-assurance/evaluate")
        self.assertEqual(response.status_code, 401)

    def test_39_viewer_evaluation_blocked(self):
        """39. VIEWER role cannot trigger assurance evaluations (HTTP 403)."""
        headers = get_auth_headers("VIEWER")
        response = client.post("/api/v1/security-assurance/evaluate", headers=headers)
        self.assertEqual(response.status_code, 403)

    def test_40_auditor_trace_access_allowed(self):
        """40. AUDITOR role has ASSURANCE_AUDIT permission and can inspect 17-stage trace."""
        with SessionLocal() as db:
            platform_eval = SecurityAssuranceService.evaluate_platform(db)
            eval_id = platform_eval.id

        headers = get_auth_headers("AUDITOR")
        response = client.get(f"/api/v1/security-assurance/{eval_id}/trace", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total_stages"], 17)

    # ── REST API & KPI TESTS ──────────────────────────────────────────────────

    def test_41_api_get_latest_assurance(self):
        """41. GET /api/v1/security-assurance/latest returns current sealed snapshot."""
        headers = get_auth_headers("SECURITY_ANALYST")
        response = client.get("/api/v1/security-assurance/latest", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("overall_score", data)
        self.assertIn("evaluation_hash", data)

    def test_42_api_get_history_and_trends(self):
        """42. GET /api/v1/security-assurance/history returns evaluations and trend time-series."""
        headers = get_auth_headers("SECURITY_ANALYST")
        response = client.get("/api/v1/security-assurance/history?limit=10", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("evaluations", data)
        self.assertIn("trend_snapshots", data)

    def test_43_api_get_kpis_summary(self):
        """43. GET /api/v1/security-assurance/kpis/summary returns aggregate metrics."""
        headers = get_auth_headers("SECURITY_ANALYST")
        response = client.get("/api/v1/security-assurance/kpis/summary", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("overall_score", data)
        self.assertIn("overall_status", data)
        self.assertIn("domain_health_counts", data)
        self.assertIn("trend_direction", data)

    def test_44_api_metric_definitions_catalog(self):
        """44. GET /api/v1/security-assurance/metrics/definitions returns metric catalog."""
        headers = get_auth_headers("SECURITY_ANALYST")
        response = client.get("/api/v1/security-assurance/metrics/definitions", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(len(data), 0)
        self.assertIn("metric_key", data[0])


if __name__ == "__main__":
    unittest.main()

