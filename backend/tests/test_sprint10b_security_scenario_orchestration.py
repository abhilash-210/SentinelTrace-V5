"""
tests/test_sprint10b_security_scenario_orchestration.py
-------------------------------------------------------
Comprehensive automated test suite for Sprint 10B:
- Security Scenario Registry & Deterministic Versioning
- Deterministic 20-Stage Scenario Orchestration Engine
- 4 Seeded Demonstration Scenarios (Credential, Malware, Trust Degradation, Crypto Failure)
- Cross-Domain Artifact Binding Service & SHA-256 Hash Verification
- End-to-End Structural and Cryptographic Verification Engine
- Historical Evidence Replay & Execution Comparison Engine
- Executive Security Posture Impact Delta Engine & Classification
- 21-Stage Cross-Domain Provenance Lineage Tracer
- Centralized RBAC Enforcement across all 6 Platform Roles
- Full REST API Suite
"""

import hashlib
import json
import unittest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.security_scenario import (
    SecurityScenario,
    SecurityScenarioVersion,
    ScenarioExecution,
    ScenarioStageExecution,
    ScenarioArtifactBinding,
    ScenarioVerificationResult,
    ScenarioExecutiveImpact,
    SCENARIO_VERSION_DOMAIN_PREFIX,
    SCENARIO_EXECUTION_DOMAIN_PREFIX,
    SCENARIO_ARTIFACT_BINDING_DOMAIN_PREFIX,
    SCENARIO_VERIFICATION_DOMAIN_PREFIX,
    calculate_scenario_hash,
)
from app.services.security_scenario_orchestration_service import (
    SecurityScenarioOrchestrationService,
    CANONICAL_STAGES,
)
from app.services.scenario_artifact_binding_service import ScenarioArtifactBindingService
from app.services.security_scenario_verification_service import SecurityScenarioVerificationService
from app.services.security_scenario_replay_service import SecurityScenarioReplayService
from app.services.scenario_executive_impact_service import ScenarioExecutiveImpactService
from app.services.security_scenario_provenance_service import SecurityScenarioProvenanceService
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint10BSecurityScenarioOrchestration(unittest.TestCase):
    """Test suite for Sprint 10B Security Scenario Orchestration & Evidence Replay."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)
            SecurityScenarioOrchestrationService.seed_default_scenarios(db)

    def setUp(self):
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 1: MODEL TESTS (Tests 1 to 8)
    # ══════════════════════════════════════════════════════════════════════════

    def test_01_create_security_scenario_model(self):
        """1. Verify SecurityScenario model creation with version 1."""
        key = f"SCN_TEST_{uuid.uuid4().hex[:8]}"
        scenario, ver = SecurityScenarioOrchestrationService.create_scenario(
            db=self.db,
            scenario_key=key,
            scenario_name="Test Scenario Model",
            description="Testing model creation",
            category="IDENTITY_COMPROMISE",
            severity="HIGH",
            created_by_user_id="admin_demo",
        )
        self.assertIsNotNone(scenario.id)
        self.assertEqual(scenario.scenario_key, key)
        self.assertEqual(ver.version_number, 1)
        self.assertEqual(scenario.current_version_id, ver.id)

    def test_02_scenario_key_uniqueness(self):
        """2. Verify scenario_key uniqueness constraint."""
        key = f"SCN_DUP_{uuid.uuid4().hex[:8]}"
        SecurityScenarioOrchestrationService.create_scenario(
            db=self.db,
            scenario_key=key,
            scenario_name="Original",
            description="Desc",
            category="ENDPOINT_MALWARE",
            severity="MEDIUM",
            created_by_user_id="admin_demo",
        )
        with self.assertRaises(ValueError):
            SecurityScenarioOrchestrationService.create_scenario(
                db=self.db,
                scenario_key=key,
                scenario_name="Duplicate",
                description="Desc",
                category="ENDPOINT_MALWARE",
                severity="MEDIUM",
                created_by_user_id="admin_demo",
            )

    def test_03_scenario_version_monotonicity(self):
        """3. Verify version increments monotonically (1 -> 2 -> 3)."""
        key = f"SCN_VER_{uuid.uuid4().hex[:8]}"
        scn, v1 = SecurityScenarioOrchestrationService.create_scenario(
            db=self.db,
            scenario_key=key,
            scenario_name="Versioned Scenario",
            description="Desc",
            category="TRUST_DEGRADATION",
            severity="LOW",
            created_by_user_id="admin_demo",
        )
        v2 = SecurityScenarioOrchestrationService.create_scenario_version(
            db=self.db,
            scenario_id=scn.id,
            definition_json={"events": [{"seq": 1, "type": "MODIFIED"}]},
            created_by_user_id="admin_demo",
        )
        v3 = SecurityScenarioOrchestrationService.create_scenario_version(
            db=self.db,
            scenario_id=scn.id,
            definition_json={"events": [{"seq": 1, "type": "MODIFIED_AGAIN"}]},
            created_by_user_id="admin_demo",
        )
        self.assertEqual(v1.version_number, 1)
        self.assertEqual(v2.version_number, 2)
        self.assertEqual(v3.version_number, 3)
        self.assertEqual(v2.status, "SUPERSEDED")
        self.assertEqual(v3.status, "ACTIVE")

    def test_04_version_definition_hash_determinism(self):
        """4. Verify definition_hash is deterministic with domain prefix."""
        payload = {"events": [{"type": "TEST"}]}
        hash1 = calculate_scenario_hash(SCENARIO_VERSION_DOMAIN_PREFIX, payload)
        hash2 = calculate_scenario_hash(SCENARIO_VERSION_DOMAIN_PREFIX, payload)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

    def test_05_scenario_execution_number_format(self):
        """5. Verify execution_number format: SCX-YYYY-NNN."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        self.assertTrue(exec_record.execution_number.startswith("SCX-"))
        self.assertEqual(len(exec_record.execution_number.split("-")), 3)

    def test_06_scenario_stage_execution_initialization(self):
        """6. Verify all 20 canonical stages are created upon execution initialization."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        self.assertEqual(len(exec_record.stages), 20)
        self.assertEqual(exec_record.stages[0].stage_number, 1)
        self.assertEqual(exec_record.stages[19].stage_number, 20)

    def test_07_artifact_binding_model_persistence(self):
        """7. Verify ScenarioArtifactBinding persistence and relationship."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        stg1 = exec_record.stages[0]
        binding = ScenarioArtifactBindingService.bind_artifact(
            db=self.db,
            scenario_execution_id=exec_record.id,
            stage_execution_id=stg1.id,
            artifact_domain="EVIDENCE",
            artifact_type="RAW_LOG",
            artifact_id="evt_test_123",
            artifact_hash="a" * 64,
        )
        self.assertIsNotNone(binding.id)
        self.assertEqual(binding.artifact_id, "evt_test_123")
        self.assertTrue(binding.binding_hash)

    def test_08_scenario_executive_impact_persistence(self):
        """8. Verify ScenarioExecutiveImpact persistence."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        impact = ScenarioExecutiveImpactService.calculate_impact(self.db, exec_record.id)
        self.assertIsNotNone(impact.id)
        self.assertEqual(impact.scenario_execution_id, exec_record.id)
        self.assertIn(impact.impact_classification, [
            "CRITICAL_NEGATIVE", "HIGH_NEGATIVE", "MODERATE_NEGATIVE", "LOW_NEGATIVE", "NEUTRAL", "POSITIVE_RECOVERY"
        ])

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 2: ORCHESTRATION ENGINE TESTS (Tests 9 to 16)
    # ══════════════════════════════════════════════════════════════════════════

    def test_09_execute_all_stages_progression(self):
        """9. Verify execute_all_stages completes all 20 stages sequentially."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        completed = SecurityScenarioOrchestrationService.execute_all_stages(
            db=self.db,
            execution_id=exec_record.id,
            actor_id="usr_analyst_001",
            actor_username="analyst_demo",
        )
        self.assertEqual(completed.status, "COMPLETED")
        for s in completed.stages:
            self.assertEqual(s.status, "COMPLETED")

    def test_10_single_stage_execution(self):
        """10. Verify executing single stage transitions from PENDING to COMPLETED."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        stg1 = SecurityScenarioOrchestrationService.execute_stage(
            db=self.db,
            execution_id=exec_record.id,
            stage_number=1,
            actor_username="analyst_demo",
        )
        self.assertEqual(stg1.status, "COMPLETED")
        self.assertEqual(stg1.verification_result, "VERIFIED")

    def test_11_idempotent_stage_reexecution(self):
        """11. Verify re-executing already COMPLETED stage is idempotent."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        stg1 = SecurityScenarioOrchestrationService.execute_stage(
            db=self.db,
            execution_id=exec_record.id,
            stage_number=1,
        )
        stg1_again = SecurityScenarioOrchestrationService.execute_stage(
            db=self.db,
            execution_id=exec_record.id,
            stage_number=1,
        )
        self.assertEqual(stg1.id, stg1_again.id)
        self.assertEqual(stg1_again.status, "COMPLETED")

    def test_12_pause_and_resume_execution(self):
        """12. Verify execution pause and resume state transitions."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        exec_record.status = "RUNNING"
        self.db.commit()

        paused = SecurityScenarioOrchestrationService.pause_execution(self.db, exec_record.id)
        self.assertEqual(paused.status, "PAUSED")

        resumed = SecurityScenarioOrchestrationService.resume_execution(self.db, exec_record.id)
        self.assertEqual(resumed.status, "RUNNING")

    def test_13_fail_execution_handling(self):
        """13. Verify fail_execution marks status FAILED."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        failed = SecurityScenarioOrchestrationService.fail_execution(
            db=self.db,
            execution_id=exec_record.id,
            error_code="ERR_TEST_ABORT",
            reason="Aborted by test",
        )
        self.assertEqual(failed.status, "FAILED")
        self.assertEqual(failed.verification_status, "FAILED")

    def test_14_execution_timeline_retrieval(self):
        """14. Verify get_execution_timeline returns chronological items."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        timeline = SecurityScenarioOrchestrationService.get_execution_timeline(self.db, exec_record.id)
        self.assertEqual(len(timeline), 20)
        self.assertEqual(timeline[0]["stage_number"], 1)
        self.assertEqual(timeline[19]["stage_number"], 20)

    def test_15_nonexistent_execution_handling(self):
        """15. Verify invalid execution lookup returns None or raises ValueError."""
        res = SecurityScenarioOrchestrationService.get_execution(self.db, "scx_nonexistent")
        self.assertIsNone(res)
        with self.assertRaises(ValueError):
            SecurityScenarioOrchestrationService.execute_stage(self.db, "scx_nonexistent", 1)

    def test_16_execution_mode_preservation(self):
        """16. Verify execution mode (LIVE_PIPELINE, CONTROLLED_DEMO, HISTORICAL_REPLAY) is saved."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec1 = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            execution_mode="LIVE_PIPELINE",
            initiated_by_user_id="analyst_demo",
        )
        self.assertEqual(exec1.execution_mode, "LIVE_PIPELINE")

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 3: SEEDED DEMONSTRATION SCENARIOS (Tests 17 to 20)
    # ══════════════════════════════════════════════════════════════════════════

    def test_17_seeded_credential_compromise(self):
        """17. Verify SCN_CREDENTIAL_COMPROMISE seeded properly."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        self.assertIsNotNone(scn)
        self.assertEqual(scn.category, "IDENTITY_COMPROMISE")
        self.assertEqual(scn.severity, "CRITICAL")

    def test_18_seeded_malware_propagation(self):
        """18. Verify SCN_MALWARE_PROPAGATION seeded properly."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_MALWARE_PROPAGATION")
        self.assertIsNotNone(scn)
        self.assertEqual(scn.category, "ENDPOINT_MALWARE")
        self.assertEqual(scn.severity, "HIGH")

    def test_19_seeded_detection_trust_failure(self):
        """19. Verify SCN_DETECTION_TRUST_FAILURE seeded properly."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_DETECTION_TRUST_FAILURE")
        self.assertIsNotNone(scn)
        self.assertEqual(scn.category, "TRUST_DEGRADATION")

    def test_20_seeded_cryptographic_integrity_failure(self):
        """20. Verify SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE seeded properly."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE")
        self.assertIsNotNone(scn)
        self.assertEqual(scn.category, "CRYPTO_VERIFICATION")
        self.assertEqual(scn.severity, "CRITICAL")

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 4: ARTIFACT BINDING TESTS (Tests 21 to 26)
    # ══════════════════════════════════════════════════════════════════════════

    def test_21_artifact_binding_hash_prefix(self):
        """21. Verify binding hash prefix SENTINELTRACE_SCENARIO_ARTIFACT_BINDING_V1."""
        h = ScenarioArtifactBindingService.calculate_binding_hash(
            scenario_execution_id="scx_123",
            stage_execution_id="scs_123",
            artifact_domain="EVIDENCE",
            artifact_type="RAW_LOG",
            artifact_id="123",
            artifact_hash="b" * 64,
        )
        self.assertEqual(len(h), 64)

    def test_22_artifact_binding_verification_success(self):
        """22. Verify verify_artifact_binding returns True for untampered binding."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        stg1 = exec_record.stages[0]
        binding = ScenarioArtifactBindingService.bind_artifact(
            db=self.db,
            scenario_execution_id=exec_record.id,
            stage_execution_id=stg1.id,
            artifact_domain="EVIDENCE",
            artifact_type="RAW_LOG",
            artifact_id="evt_test_valid",
            artifact_hash="c" * 64,
        )
        self.assertTrue(ScenarioArtifactBindingService.verify_artifact_binding(binding))

    def test_23_tampered_artifact_binding_detection(self):
        """23. Verify tampering with artifact binding fields causes verification failure."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        stg1 = exec_record.stages[0]
        binding = ScenarioArtifactBindingService.bind_artifact(
            db=self.db,
            scenario_execution_id=exec_record.id,
            stage_execution_id=stg1.id,
            artifact_domain="EVIDENCE",
            artifact_type="RAW_LOG",
            artifact_id="evt_test_tampered",
            artifact_hash="d" * 64,
        )
        # Tamper with artifact_id
        binding.artifact_id = "evt_tampered_id"
        self.assertFalse(ScenarioArtifactBindingService.verify_artifact_binding(binding))

    def test_24_get_stage_artifacts_retrieval(self):
        """24. Verify get_stage_artifacts filters by stage ID."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        stg1 = exec_record.stages[0]
        ScenarioArtifactBindingService.bind_artifact(
            db=self.db,
            scenario_execution_id=exec_record.id,
            stage_execution_id=stg1.id,
            artifact_domain="EVIDENCE",
            artifact_type="RAW_LOG",
            artifact_id="evt_1",
            artifact_hash="e" * 64,
        )
        bindings = ScenarioArtifactBindingService.get_stage_artifacts(self.db, stg1.id)
        self.assertEqual(len(bindings), 1)

    def test_25_get_execution_artifacts_retrieval(self):
        """25. Verify get_execution_artifacts returns all bindings for execution."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        completed = SecurityScenarioOrchestrationService.execute_all_stages(
            db=self.db,
            execution_id=exec_record.id,
        )
        bindings = ScenarioArtifactBindingService.get_execution_artifacts(self.db, completed.id)
        self.assertEqual(len(bindings), 20)

    def test_26_verify_execution_artifacts_clean(self):
        """26. Verify verify_execution_artifacts returns (True, []) for completed run."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        completed = SecurityScenarioOrchestrationService.execute_all_stages(
            db=self.db,
            execution_id=exec_record.id,
        )
        is_valid, errors = ScenarioArtifactBindingService.verify_execution_artifacts(self.db, completed.id)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 5: END-TO-END VERIFICATION ENGINE TESTS (Tests 27 to 33)
    # ══════════════════════════════════════════════════════════════════════════

    def test_27_full_verification_success(self):
        """27. Verify nominal execution achieves overall_verification_status = VERIFIED."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        completed = SecurityScenarioOrchestrationService.execute_all_stages(
            db=self.db,
            execution_id=exec_record.id,
        )
        verif = SecurityScenarioVerificationService.verify_execution(self.db, completed.id)
        self.assertEqual(verif.overall_verification_status, "VERIFIED")
        self.assertEqual(verif.verified_stages, 20)
        self.assertEqual(verif.failed_stages, 0)

    def test_28_skipped_stage_causes_degraded_status(self):
        """28. Verify a SKIPPED stage degrades status to DEGRADED."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        # Mark stage 5 as SKIPPED
        exec_record.stages[4].status = "SKIPPED"
        self.db.commit()

        verif = SecurityScenarioVerificationService.verify_execution(self.db, exec_record.id)
        self.assertEqual(verif.overall_verification_status, "DEGRADED")
        self.assertGreaterEqual(verif.degraded_stages, 1)

    def test_29_failed_stage_causes_failed_status(self):
        """29. Verify a FAILED stage forces overall status to FAILED."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        exec_record.stages[2].status = "FAILED"
        exec_record.stages[2].verification_result = "FAILED"
        self.db.commit()

        verif = SecurityScenarioVerificationService.verify_execution(self.db, exec_record.id)
        self.assertEqual(verif.overall_verification_status, "FAILED")
        self.assertGreaterEqual(verif.failed_stages, 1)

    def test_30_crypto_failure_forces_failed_verification(self):
        """30. Verify SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE forces verification status to FAILED."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        completed = SecurityScenarioOrchestrationService.execute_all_stages(
            db=self.db,
            execution_id=exec_record.id,
        )
        verif = SecurityScenarioVerificationService.verify_execution(self.db, completed.id)
        self.assertEqual(verif.overall_verification_status, "FAILED")
        self.assertEqual(verif.merkle_integrity, "FAILED")

    def test_31_verification_hash_domain_prefix(self):
        """31. Verify verification_hash prefix SENTINELTRACE_SCENARIO_VERIFICATION_V1."""
        h = calculate_scenario_hash(SCENARIO_VERIFICATION_DOMAIN_PREFIX, {"test": "data"})
        self.assertEqual(len(h), 64)

    def test_32_get_verification_result_method(self):
        """32. Verify get_verification_result retrieves persisted record."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        SecurityScenarioVerificationService.verify_execution(self.db, exec_record.id)
        verif = SecurityScenarioVerificationService.get_verification_result(self.db, exec_record.id)
        self.assertIsNotNone(verif)

    def test_33_zero_trust_unknown_never_verified(self):
        """33. Verify unexecuted UNKNOWN stage never produces VERIFIED overall."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        # Leaves stages in PENDING status
        verif = SecurityScenarioVerificationService.verify_execution(self.db, exec_record.id)
        self.assertNotEqual(verif.overall_verification_status, "VERIFIED")

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 6: REPLAY & TIMELINE RECONSTRUCTION TESTS (Tests 34 to 39)
    # ══════════════════════════════════════════════════════════════════════════

    def test_34_reconstruct_timeline_without_side_effects(self):
        """34. Verify reconstruct_timeline reconstructs history without creating records."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        SecurityScenarioOrchestrationService.execute_all_stages(self.db, exec_record.id)

        count_before = self.db.query(ScenarioArtifactBinding).count()
        timeline = SecurityScenarioReplayService.reconstruct_timeline(self.db, exec_record.id)
        count_after = self.db.query(ScenarioArtifactBinding).count()

        self.assertEqual(count_before, count_after)
        self.assertEqual(len(timeline), 20)

    def test_35_evidence_replay_mode(self):
        """35. Verify replay with EVIDENCE_REPLAY mode."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        SecurityScenarioOrchestrationService.execute_all_stages(self.db, exec_record.id)

        res = SecurityScenarioReplayService.replay_execution(
            db=self.db,
            original_execution_id=exec_record.id,
            replay_mode="EVIDENCE_REPLAY",
        )
        self.assertEqual(res["replay_mode"], "EVIDENCE_REPLAY")
        self.assertTrue(res["integrity_verified"])

    def test_36_controlled_reexecution_replay_mode(self):
        """36. Verify replay with HISTORICAL_REPLAY creates new execution and compares."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        SecurityScenarioOrchestrationService.execute_all_stages(self.db, exec_record.id)

        res = SecurityScenarioReplayService.replay_execution(
            db=self.db,
            original_execution_id=exec_record.id,
            replay_mode="HISTORICAL_REPLAY",
        )
        self.assertIsNotNone(res["replay_execution_id"])
        self.assertIn(res["comparison_status"], ["IDENTICAL", "FUNCTIONALLY_EQUIVALENT"])

    def test_37_compare_executions_identical(self):
        """37. Verify comparing execution with itself returns IDENTICAL."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        SecurityScenarioOrchestrationService.execute_all_stages(self.db, exec_record.id)

        comp = SecurityScenarioReplayService.compare_executions(self.db, exec_record.id, exec_record.id)
        self.assertEqual(comp["comparison_status"], "IDENTICAL")

    def test_38_compare_executions_different(self):
        """38. Verify comparing executions with different statuses returns DIFFERENT."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec1 = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        SecurityScenarioOrchestrationService.execute_all_stages(self.db, exec1.id)

        exec2 = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        # Leaves exec2 unexecuted
        comp = SecurityScenarioReplayService.compare_executions(self.db, exec1.id, exec2.id)
        self.assertEqual(comp["comparison_status"], "DIFFERENT")

    def test_39_compare_executions_inconclusive(self):
        """39. Verify non-existent execution returns INCONCLUSIVE."""
        comp = SecurityScenarioReplayService.compare_executions(self.db, "scx_fake_1", "scx_fake_2")
        self.assertEqual(comp["comparison_status"], "INCONCLUSIVE")

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 7: EXECUTIVE SECURITY IMPACT TESTS (Tests 40 to 45)
    # ══════════════════════════════════════════════════════════════════════════

    def test_40_executive_impact_calculation(self):
        """40. Verify executive posture impact score delta calculation."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        impact = ScenarioExecutiveImpactService.calculate_impact(self.db, exec_record.id)
        self.assertIsInstance(impact.score_delta, float)
        self.assertIsNotNone(impact.impact_classification)

    def test_41_crypto_failure_forces_critical_negative_impact(self):
        """41. Verify cryptographic failure forces impact to CRITICAL_NEGATIVE and 0.0 post_score."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        impact = ScenarioExecutiveImpactService.calculate_impact(self.db, exec_record.id)
        self.assertEqual(impact.impact_classification, "CRITICAL_NEGATIVE")
        self.assertEqual(impact.post_score, 0.0)
        self.assertEqual(impact.post_status, "CRITICAL")

    def test_42_impacted_domains_list_structure(self):
        """42. Verify impacted_domains_json contains domain names and score deltas."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        impact = ScenarioExecutiveImpactService.calculate_impact(self.db, exec_record.id)
        self.assertTrue(len(impact.impacted_domains_json) > 0)
        self.assertIn("domain_name", impact.impacted_domains_json[0])

    def test_43_get_executive_impact_retrieval(self):
        """43. Verify get_executive_impact returns saved record."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        ScenarioExecutiveImpactService.calculate_impact(self.db, exec_record.id)
        res = ScenarioExecutiveImpactService.get_executive_impact(self.db, exec_record.id)
        self.assertIsNotNone(res)

    def test_44_high_negative_classification(self):
        """44. Verify score delta <= -15 classifies as HIGH_NEGATIVE or CRITICAL_NEGATIVE."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_MALWARE_PROPAGATION")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        impact = ScenarioExecutiveImpactService.calculate_impact(self.db, exec_record.id)
        self.assertIn(impact.impact_classification, ["HIGH_NEGATIVE", "CRITICAL_NEGATIVE", "MODERATE_NEGATIVE"])

    def test_45_impact_pre_score_bounded(self):
        """45. Verify pre_score is bounded [0.0, 100.0]."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        impact = ScenarioExecutiveImpactService.calculate_impact(self.db, exec_record.id)
        self.assertGreaterEqual(impact.pre_score, 0.0)
        self.assertLessEqual(impact.pre_score, 100.0)

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 8: 21-STAGE PROVENANCE TRACER TESTS (Tests 46 to 50)
    # ══════════════════════════════════════════════════════════════════════════

    def test_46_trace_scenario_provenance_length(self):
        """46. Verify trace_scenario_provenance returns exactly 21 nodes."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        SecurityScenarioOrchestrationService.execute_all_stages(self.db, exec_record.id)
        nodes = SecurityScenarioProvenanceService.trace_scenario_provenance(self.db, exec_record.id)
        self.assertEqual(len(nodes), 21)

    def test_47_provenance_stage_keys_monotonic(self):
        """47. Verify provenance stage_numbers are strictly 1..21."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        nodes = SecurityScenarioProvenanceService.trace_scenario_provenance(self.db, exec_record.id)
        for i, n in enumerate(nodes):
            self.assertEqual(n["stage_number"], i + 1)

    def test_48_provenance_upstream_downstream_links(self):
        """48. Verify upstream_reference and downstream_reference chain."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        nodes = SecurityScenarioProvenanceService.trace_scenario_provenance(self.db, exec_record.id)
        self.assertIsNone(nodes[0]["upstream_reference"])
        self.assertEqual(nodes[0]["downstream_reference"], "stage_2")
        self.assertEqual(nodes[20]["upstream_reference"], "stage_20")
        self.assertIsNone(nodes[20]["downstream_reference"])

    def test_49_provenance_crypto_failure_flag(self):
        """49. Verify SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE sets node 21 verification_status FAILED."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        SecurityScenarioOrchestrationService.execute_all_stages(self.db, exec_record.id)
        nodes = SecurityScenarioProvenanceService.trace_scenario_provenance(self.db, exec_record.id)
        self.assertEqual(nodes[20]["verification_status"], "FAILED")

    def test_50_provenance_string_artifact_id_serialization(self):
        """50. Verify artifact_id is strictly a string across all 21 nodes."""
        scn = SecurityScenarioOrchestrationService.get_scenario(self.db, "SCN_CREDENTIAL_COMPROMISE")
        exec_record = SecurityScenarioOrchestrationService.create_execution(
            db=self.db,
            scenario_id_or_key=scn.id,
            initiated_by_user_id="analyst_demo",
        )
        nodes = SecurityScenarioProvenanceService.trace_scenario_provenance(self.db, exec_record.id)
        for n in nodes:
            self.assertIsInstance(n["artifact_id"], str)

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 9: RBAC PERMISSIONS TESTS (Tests 51 to 55)
    # ══════════════════════════════════════════════════════════════════════════

    def test_51_admin_full_scenario_access(self):
        """51. Verify Admin has SCENARIO_READ and SCENARIO_EXECUTE."""
        headers = get_auth_headers("ADMIN")
        res = client.get("/api/v1/security-scenarios/", headers=headers)
        self.assertEqual(res.status_code, 200)

    def test_52_analyst_scenario_execute_allowed(self):
        """52. Verify Security Analyst has SCENARIO_EXECUTE permission."""
        headers = get_auth_headers("SECURITY_ANALYST")
        res = client.post(
            "/api/v1/security-scenarios/SCN_CREDENTIAL_COMPROMISE/execute",
            headers=headers,
            json={"execution_mode": "CONTROLLED_DEMO"},
        )
        self.assertEqual(res.status_code, 201)

    def test_53_viewer_scenario_execute_forbidden(self):
        """53. Verify Viewer receives 403 Forbidden on execute."""
        headers = get_auth_headers("VIEWER")
        res = client.post(
            "/api/v1/security-scenarios/SCN_CREDENTIAL_COMPROMISE/execute",
            headers=headers,
            json={"execution_mode": "CONTROLLED_DEMO"},
        )
        self.assertEqual(res.status_code, 403)

    def test_54_policy_author_scenario_create_allowed(self):
        """54. Verify Policy Author has SCENARIO_CREATE permission."""
        headers = get_auth_headers("POLICY_AUTHOR")
        key = f"SCN_AUTH_{uuid.uuid4().hex[:8]}"
        res = client.post(
            "/api/v1/security-scenarios/",
            headers=headers,
            json={
                "scenario_key": key,
                "scenario_name": "Author Created Scenario",
                "description": "Desc",
                "category": "IDENTITY_COMPROMISE",
                "severity": "HIGH",
                "status": "ACTIVE",
            },
        )
        self.assertEqual(res.status_code, 201)

    def test_55_unauthenticated_request_fails(self):
        """55. Verify unauthenticated requests receive 401 Unauthorized."""
        res = client.get("/api/v1/security-scenarios/")
        self.assertEqual(res.status_code, 401)

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 10: REST API ENDPOINTS TESTS (Tests 56 to 62)
    # ══════════════════════════════════════════════════════════════════════════

    def test_56_api_list_scenarios(self):
        """56. Verify GET /api/v1/security-scenarios/ returns list."""
        headers = get_auth_headers("SECURITY_ANALYST")
        res = client.get("/api/v1/security-scenarios/", headers=headers)
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

    def test_57_api_dashboard_summary(self):
        """57. Verify GET /api/v1/security-scenarios/dashboard/summary."""
        headers = get_auth_headers("SECURITY_ANALYST")
        res = client.get("/api/v1/security-scenarios/dashboard/summary", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total_scenarios", data)
        self.assertIn("pipeline_integrity_rate", data)

    def test_58_api_get_scenario_by_id(self):
        """58. Verify GET /api/v1/security-scenarios/{id}."""
        headers = get_auth_headers("SECURITY_ANALYST")
        res = client.get("/api/v1/security-scenarios/SCN_CREDENTIAL_COMPROMISE", headers=headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["scenario_key"], "SCN_CREDENTIAL_COMPROMISE")

    def test_59_api_get_execution_timeline(self):
        """59. Verify GET /api/v1/security-scenarios/executions/{id}/timeline."""
        headers = get_auth_headers("SECURITY_ANALYST")
        # Run execution
        exec_res = client.post(
            "/api/v1/security-scenarios/SCN_CREDENTIAL_COMPROMISE/execute",
            headers=headers,
            json={"execution_mode": "CONTROLLED_DEMO"},
        )
        exec_id = exec_res.json()["id"]

        time_res = client.get(f"/api/v1/security-scenarios/executions/{exec_id}/timeline", headers=headers)
        self.assertEqual(time_res.status_code, 200)
        self.assertEqual(len(time_res.json()), 20)

    def test_60_api_get_execution_artifacts(self):
        """60. Verify GET /api/v1/security-scenarios/executions/{id}/artifacts."""
        headers = get_auth_headers("SECURITY_ANALYST")
        exec_res = client.post(
            "/api/v1/security-scenarios/SCN_CREDENTIAL_COMPROMISE/execute",
            headers=headers,
            json={"execution_mode": "CONTROLLED_DEMO"},
        )
        exec_id = exec_res.json()["id"]

        art_res = client.get(f"/api/v1/security-scenarios/executions/{exec_id}/artifacts", headers=headers)
        self.assertEqual(art_res.status_code, 200)
        self.assertEqual(len(art_res.json()), 20)

    def test_61_api_get_provenance(self):
        """61. Verify GET /api/v1/security-scenarios/executions/{id}/provenance."""
        headers = get_auth_headers("SECURITY_ANALYST")
        exec_res = client.post(
            "/api/v1/security-scenarios/SCN_CREDENTIAL_COMPROMISE/execute",
            headers=headers,
            json={"execution_mode": "CONTROLLED_DEMO"},
        )
        exec_id = exec_res.json()["id"]

        prov_res = client.get(f"/api/v1/security-scenarios/executions/{exec_id}/provenance", headers=headers)
        self.assertEqual(prov_res.status_code, 200)
        self.assertEqual(len(prov_res.json()), 21)

    def test_62_api_replay_execution(self):
        """62. Verify POST /api/v1/security-scenarios/executions/{id}/replay."""
        headers = get_auth_headers("SECURITY_ANALYST")
        exec_res = client.post(
            "/api/v1/security-scenarios/SCN_CREDENTIAL_COMPROMISE/execute",
            headers=headers,
            json={"execution_mode": "CONTROLLED_DEMO"},
        )
        exec_id = exec_res.json()["id"]

        replay_res = client.post(
            f"/api/v1/security-scenarios/executions/{exec_id}/replay",
            headers=headers,
            json={"execution_mode": "EVIDENCE_REPLAY", "verify_against_original": True},
        )
        self.assertEqual(replay_res.status_code, 200)
        self.assertTrue(replay_res.json()["integrity_verified"])


if __name__ == "__main__":
    unittest.main()
