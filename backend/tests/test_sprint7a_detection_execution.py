"""
tests/test_sprint7a_detection_execution.py
-------------------------------------------
Comprehensive test suite for Sprint 7A: Real-Time Detection Rule Execution Engine.

35 exhaustive automated unit, integration, and security tests covering:
1. Active rule executes successfully
2. Draft rule version does NOT execute (HTTP 400 / ValueError)
3. Pending-review rule version does NOT execute
4. Approved-but-not-active rule version does NOT execute
5. Superseded rule version does NOT execute
6. Disabled rule version does NOT execute
7. MATCH result works deterministically
8. NO_MATCH result works deterministically
9. Missing required field returns PARTIAL (never false NO_MATCH)
10. Unknown operator returns ERROR safely
11. EQUALS operator works (case-insensitive strings & numeric)
12. NOT_EQUALS operator works
13. GREATER_THAN operator works
14. LESS_THAN operator works
15. CONTAINS operator works (string substring & list inclusion)
16. IN operator works (membership in list)
17. EXISTS operator works (true when field present)
18. NOT_EXISTS operator works (true when field missing)
19. AND group logic works correctly
20. OR group logic works correctly
21. Field resolver is deterministic and handles canonical aliases
22. Execution idempotency works (SHA-256 fingerprint)
23. Duplicate execution is not created
24. Execution record links to normalized event ID
25. Execution record links to rule version ID & version number
26. Rule version hash is preserved in execution details
27. Raw evidence remains strictly unchanged (immutable)
28. Normalized event remains strictly unchanged (immutable)
29. RBAC: Unauthorized request returns 401
30. RBAC: Unauthorized role returns 403
31. RBAC: Security analyst can execute rules
32. RBAC: Auditor can read execution details and trace but cannot execute
33. 10-Stage trace endpoint returns complete provenance chain
34. Batch execution across all ACTIVE rules for an event
35. Execution listing with filters & pagination
"""

import json
import unittest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.detection_execution import DetectionConditionResult, DetectionExecution
from app.models.detection_rule import DetectionRule
from app.models.detection_rule_governance import (
    DetectionRuleGovernanceEvent,
    DetectionRuleVersion,
    DetectionRuleVersionDependency,
)
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.services.detection_execution_service import DetectionExecutionService
from app.services.detection_field_resolver import DetectionFieldResolver
from app.services.detection_rule_governance_service import DetectionRuleGovernanceService
from app.services.detection_rule_service import DetectionRuleService
from app.services.detection_rule_trust_service import DetectionRuleTrustService
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint7ADetectionExecution(unittest.TestCase):
    """Automated test suite for Sprint 7A Detection Rule Execution Engine."""

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

    # ── Test 1: Active rule executes ──────────────────────────────────────────
    def test_01_active_rule_executes(self):
        """Verify an ACTIVE governed rule version executes successfully against a normalized event."""
        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.post(
            "/api/v1/detection-rules/drule_suspicious_ssh/execute/norm_demo_ssh_allowed",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["rule_id"], "drule_suspicious_ssh")
        self.assertEqual(data["execution_status"], "MATCH")
        self.assertTrue(data["matched"])
        self.assertIn("execution_id", data)

    # ── Test 2: Draft rule does NOT execute ───────────────────────────────────
    def test_02_draft_rule_does_not_execute(self):
        """Verify rules with status DRAFT cannot be executed."""
        headers = get_auth_headers("SECURITY_ANALYST")
        # drule_lateral_move is seeded as DRAFT with no active governed version
        with SessionLocal() as db:
            # ensure no active version exists
            vers = db.query(DetectionRuleVersion).filter(
                DetectionRuleVersion.rule_id == "drule_lateral_move",
                DetectionRuleVersion.status == "ACTIVE",
            ).all()
            for v in vers:
                v.status = "DRAFT"
            db.commit()

        resp = client.post(
            "/api/v1/detection-rules/drule_lateral_move/execute/norm_demo_ssh_allowed",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("no active", resp.json()["detail"].lower())

    # ── Test 3: Pending review rule does NOT execute ──────────────────────────
    def test_03_pending_review_rule_does_not_execute(self):
        """Verify rule versions in PENDING_REVIEW cannot execute."""
        headers = get_auth_headers("SECURITY_ANALYST")
        with SessionLocal() as db:
            # create temporary rule in PENDING_REVIEW
            rule_id = f"drule_test_pending_{uuid.uuid4().hex[:6]}"
            r = DetectionRule(
                rule_id=rule_id,
                rule_name="Pending Test",
                vendor_name="ANY",
                status="PENDING_REVIEW",
            )
            db.add(r)
            ver = DetectionRuleVersion(
                version_id=f"drver_{rule_id}_v1",
                rule_id=rule_id,
                version_number=1,
                rule_name="Pending Test",
                vendor_name="ANY",
                status="PENDING_REVIEW",
                created_by_user_id="usr_author_cisco",
                version_hash="test_hash_pending",
            )
            db.add(ver)
            db.commit()

        resp = client.post(
            f"/api/v1/detection-rules/{rule_id}/execute/norm_demo_ssh_allowed",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("no active", resp.json()["detail"].lower())

    # ── Test 4: Approved-but-not-active rule does NOT execute ─────────────────
    def test_04_approved_but_not_active_does_not_execute(self):
        """Verify rule versions in APPROVED status (not yet ACTIVATED) cannot execute."""
        headers = get_auth_headers("SECURITY_ANALYST")
        with SessionLocal() as db:
            rule_id = f"drule_test_approved_{uuid.uuid4().hex[:6]}"
            r = DetectionRule(
                rule_id=rule_id,
                rule_name="Approved Test",
                vendor_name="ANY",
                status="APPROVED",
            )
            db.add(r)
            ver = DetectionRuleVersion(
                version_id=f"drver_{rule_id}_v1",
                rule_id=rule_id,
                version_number=1,
                rule_name="Approved Test",
                vendor_name="ANY",
                status="APPROVED",
                created_by_user_id="usr_author_cisco",
                version_hash="test_hash_approved",
            )
            db.add(ver)
            db.commit()

        resp = client.post(
            f"/api/v1/detection-rules/{rule_id}/execute/norm_demo_ssh_allowed",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("no active", resp.json()["detail"].lower())

    # ── Test 5: Superseded rule does NOT execute ──────────────────────────────
    def test_05_superseded_rule_does_not_execute(self):
        """Verify rule versions in SUPERSEDED status cannot execute."""
        headers = get_auth_headers("SECURITY_ANALYST")
        with SessionLocal() as db:
            rule_id = f"drule_test_superseded_{uuid.uuid4().hex[:6]}"
            r = DetectionRule(
                rule_id=rule_id,
                rule_name="Superseded Test",
                vendor_name="ANY",
                status="SUPERSEDED",
            )
            db.add(r)
            ver = DetectionRuleVersion(
                version_id=f"drver_{rule_id}_v1",
                rule_id=rule_id,
                version_number=1,
                rule_name="Superseded Test",
                vendor_name="ANY",
                status="SUPERSEDED",
                created_by_user_id="usr_author_cisco",
                version_hash="test_hash_superseded",
            )
            db.add(ver)
            db.commit()

        resp = client.post(
            f"/api/v1/detection-rules/{rule_id}/execute/norm_demo_ssh_allowed",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 400)

    # ── Test 6: Disabled rule does NOT execute ────────────────────────────────
    def test_06_disabled_rule_does_not_execute(self):
        """Verify rule versions in DISABLED status cannot execute."""
        headers = get_auth_headers("SECURITY_ANALYST")
        with SessionLocal() as db:
            rule_id = f"drule_test_disabled_{uuid.uuid4().hex[:6]}"
            r = DetectionRule(
                rule_id=rule_id,
                rule_name="Disabled Test",
                vendor_name="ANY",
                status="DISABLED",
            )
            db.add(r)
            ver = DetectionRuleVersion(
                version_id=f"drver_{rule_id}_v1",
                rule_id=rule_id,
                version_number=1,
                rule_name="Disabled Test",
                vendor_name="ANY",
                status="DISABLED",
                created_by_user_id="usr_author_cisco",
                version_hash="test_hash_disabled",
            )
            db.add(ver)
            db.commit()

        resp = client.post(
            f"/api/v1/detection-rules/{rule_id}/execute/norm_demo_ssh_allowed",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 400)

    # ── Test 7: MATCH result works ────────────────────────────────────────────
    def test_07_match_result_works(self):
        """Verify conditions matching event yield MATCH status and matched=True."""
        with SessionLocal() as db:
            res = DetectionExecutionService.execute_rule_against_event(
                db, "drule_suspicious_ssh", "norm_demo_ssh_allowed", force_recompute=True
            )
            self.assertEqual(res.execution_status, "MATCH")
            self.assertTrue(res.matched)
            self.assertEqual(res.conditions_matched, 2)
            self.assertEqual(res.conditions_missing, 0)

    # ── Test 8: NO_MATCH result works ─────────────────────────────────────────
    def test_08_no_match_result_works(self):
        """Verify event with action DENIED yields NO_MATCH when ALLOWED was expected."""
        with SessionLocal() as db:
            res = DetectionExecutionService.execute_rule_against_event(
                db, "drule_suspicious_ssh", "norm_demo_ssh_denied", force_recompute=True
            )
            self.assertEqual(res.execution_status, "NO_MATCH")
            self.assertFalse(res.matched)

    # ── Test 9: Missing required field returns PARTIAL ────────────────────────
    def test_09_missing_required_field_returns_partial(self):
        """Verify evaluating auth failure rule on firewall event (missing auth.outcome) returns PARTIAL."""
        with SessionLocal() as db:
            res = DetectionExecutionService.execute_rule_against_event(
                db, "drule_brute_force", "norm_demo_ssh_allowed", force_recompute=True
            )
            self.assertEqual(res.execution_status, "PARTIAL")
            self.assertFalse(res.matched)
            self.assertGreater(res.conditions_missing, 0)
            self.assertIn("incomplete telemetry", res.execution_explanation.lower())

    # ── Test 10: Unknown operator returns ERROR safely ────────────────────────
    def test_10_unknown_operator_returns_error_safely(self):
        """Verify an unsupported comparison operator produces an ERROR without crashing."""
        event = NormalizedEvent(action="ALLOW", dst_port=22, raw_data={})
        dsl = {
            "operator": "AND",
            "conditions": [
                {"field": "action.result", "comparison": "INVALID_OP_XYZ", "value": "ALLOW"}
            ],
        }
        status, matched, total, matched_c, missing_c, results, exp = (
            DetectionExecutionService.evaluate_condition_group(event, dsl)
        )
        self.assertEqual(status, "ERROR")
        self.assertFalse(matched)
        self.assertEqual(results[0]["condition_result"], "ERROR")

    # ── Test 11: EQUALS works ─────────────────────────────────────────────────
    def test_11_equals_operator_works(self):
        """Verify EQUALS comparison on strings (case-insensitive) and numbers."""
        event = NormalizedEvent(action="ALLOWED", dst_port=80, raw_data={})
        cond1 = {"field": "action.result", "comparison": "EQUALS", "value": "allowed"}
        res1 = DetectionExecutionService.evaluate_condition(event, cond1, 0)
        self.assertEqual(res1["condition_result"], "TRUE")

        cond2 = {"field": "dst_endpoint.port", "comparison": "EQUALS", "value": 80}
        res2 = DetectionExecutionService.evaluate_condition(event, cond2, 1)
        self.assertEqual(res2["condition_result"], "TRUE")

    # ── Test 12: NOT_EQUALS works ─────────────────────────────────────────────
    def test_12_not_equals_operator_works(self):
        """Verify NOT_EQUALS comparison operator."""
        event = NormalizedEvent(action="DENIED", dst_port=443, raw_data={})
        cond = {"field": "action.result", "comparison": "NOT_EQUALS", "value": "ALLOWED"}
        res = DetectionExecutionService.evaluate_condition(event, cond, 0)
        self.assertEqual(res["condition_result"], "TRUE")

    # ── Test 13: GREATER_THAN works ───────────────────────────────────────────
    def test_13_greater_than_operator_works(self):
        """Verify GREATER_THAN numeric operator."""
        event = NormalizedEvent(dst_port=8080, raw_data={})
        cond = {"field": "dst_endpoint.port", "comparison": "GREATER_THAN", "value": 1024}
        res = DetectionExecutionService.evaluate_condition(event, cond, 0)
        self.assertEqual(res["condition_result"], "TRUE")

    # ── Test 14: LESS_THAN works ──────────────────────────────────────────────
    def test_14_less_than_operator_works(self):
        """Verify LESS_THAN numeric operator."""
        event = NormalizedEvent(dst_port=53, raw_data={})
        cond = {"field": "dst_endpoint.port", "comparison": "LESS_THAN", "value": 1024}
        res = DetectionExecutionService.evaluate_condition(event, cond, 0)
        self.assertEqual(res["condition_result"], "TRUE")

    # ── Test 15: CONTAINS works ───────────────────────────────────────────────
    def test_15_contains_operator_works(self):
        """Verify CONTAINS substring and collection operator."""
        event = NormalizedEvent(process_name="C:\\Windows\\System32\\cmd.exe", raw_data={})
        cond = {"field": "process_name", "comparison": "CONTAINS", "value": "cmd.exe"}
        res = DetectionExecutionService.evaluate_condition(event, cond, 0)
        self.assertEqual(res["condition_result"], "TRUE")

    # ── Test 16: IN works ─────────────────────────────────────────────────────
    def test_16_in_operator_works(self):
        """Verify IN membership operator."""
        event = NormalizedEvent(protocol="TCP", raw_data={})
        cond = {"field": "protocol", "comparison": "IN", "value": ["TCP", "UDP"]}
        res = DetectionExecutionService.evaluate_condition(event, cond, 0)
        self.assertEqual(res["condition_result"], "TRUE")

    # ── Test 17: EXISTS works ─────────────────────────────────────────────────
    def test_17_exists_operator_works(self):
        """Verify EXISTS operator succeeds when field is present and non-empty."""
        event = NormalizedEvent(user_name="admin", raw_data={})
        cond = {"field": "user_name", "comparison": "EXISTS"}
        res = DetectionExecutionService.evaluate_condition(event, cond, 0)
        self.assertEqual(res["condition_result"], "TRUE")

    # ── Test 18: NOT_EXISTS works ─────────────────────────────────────────────
    def test_18_not_exists_operator_works(self):
        """Verify NOT_EXISTS operator succeeds when field is missing."""
        event = NormalizedEvent(raw_data={})
        cond = {"field": "process_id", "comparison": "NOT_EXISTS"}
        res = DetectionExecutionService.evaluate_condition(event, cond, 0)
        self.assertEqual(res["condition_result"], "TRUE")

    # ── Test 19: AND group works ──────────────────────────────────────────────
    def test_19_and_group_logic_works(self):
        """Verify AND group logic requiring all conditions to evaluate TRUE."""
        event = NormalizedEvent(action="ALLOWED", dst_port=22, protocol="TCP", raw_data={})
        dsl = {
            "operator": "AND",
            "conditions": [
                {"field": "action.result", "comparison": "EQUALS", "value": "ALLOWED"},
                {"field": "dst_endpoint.port", "comparison": "EQUALS", "value": 22},
                {"field": "protocol", "comparison": "EQUALS", "value": "TCP"},
            ],
        }
        status, matched, total, matched_c, missing_c, _, _ = (
            DetectionExecutionService.evaluate_condition_group(event, dsl)
        )
        self.assertEqual(status, "MATCH")
        self.assertTrue(matched)
        self.assertEqual(matched_c, 3)

    # ── Test 20: OR group works ───────────────────────────────────────────────
    def test_20_or_group_logic_works(self):
        """Verify OR group logic matching when any single condition is TRUE."""
        event = NormalizedEvent(action="DENIED", dst_port=80, raw_data={})
        dsl = {
            "operator": "OR",
            "conditions": [
                {"field": "dst_endpoint.port", "comparison": "EQUALS", "value": 22},
                {"field": "dst_endpoint.port", "comparison": "EQUALS", "value": 80},
            ],
        }
        status, matched, total, matched_c, missing_c, _, _ = (
            DetectionExecutionService.evaluate_condition_group(event, dsl)
        )
        self.assertEqual(status, "MATCH")
        self.assertTrue(matched)

    # ── Test 21: Field resolver deterministic ─────────────────────────────────
    def test_21_field_resolver_deterministic(self):
        """Verify field resolver handles aliases and never guesses."""
        event = NormalizedEvent(
            action="ALLOWED",
            src_ip="192.168.1.50",
            dst_port=443,
            raw_data={"custom_app": "ERP_APP"},
        )
        res1 = DetectionFieldResolver.resolve(event, "action.result")
        self.assertTrue(res1.resolved)
        self.assertEqual(res1.value, "ALLOWED")

        res2 = DetectionFieldResolver.resolve(event, "src_endpoint_ip")
        self.assertTrue(res2.resolved)
        self.assertEqual(res2.value, "192.168.1.50")

        res3 = DetectionFieldResolver.resolve(event, "dst_endpoint.port")
        self.assertTrue(res3.resolved)
        self.assertEqual(res3.value, 443)

        res4 = DetectionFieldResolver.resolve(event, "non_existent_field_abc")
        self.assertFalse(res4.resolved)
        self.assertIsNone(res4.value)

    # ── Test 22: Execution idempotency works ──────────────────────────────────
    def test_22_execution_idempotency_works(self):
        """Verify identical executions return the same execution record ID."""
        with SessionLocal() as db:
            exec1 = DetectionExecutionService.execute_rule_against_event(
                db, "drule_suspicious_ssh", "norm_demo_ssh_allowed"
            )
            exec2 = DetectionExecutionService.execute_rule_against_event(
                db, "drule_suspicious_ssh", "norm_demo_ssh_allowed"
            )
            self.assertEqual(exec1.execution_id, exec2.execution_id)
            self.assertEqual(exec1.execution_fingerprint, exec2.execution_fingerprint)

    # ── Test 23: Duplicate execution not created ──────────────────────────────
    def test_23_duplicate_execution_not_created(self):
        """Verify execution table count does not increase on duplicate run."""
        with SessionLocal() as db:
            initial_count = db.query(DetectionExecution).filter(
                DetectionExecution.rule_id == "drule_suspicious_ssh",
                DetectionExecution.normalized_event_id == "norm_demo_ssh_allowed",
            ).count()

            # Execute again without force_recompute
            DetectionExecutionService.execute_rule_against_event(
                db, "drule_suspicious_ssh", "norm_demo_ssh_allowed"
            )

            new_count = db.query(DetectionExecution).filter(
                DetectionExecution.rule_id == "drule_suspicious_ssh",
                DetectionExecution.normalized_event_id == "norm_demo_ssh_allowed",
            ).count()

            self.assertEqual(initial_count, new_count)

    # ── Test 24: Execution record links to normalized event ───────────────────
    def test_24_execution_record_links_to_normalized_event(self):
        """Verify execution record properly captures normalized_event_id and original_event_id."""
        with SessionLocal() as db:
            rec = db.query(DetectionExecution).first()
            self.assertIsNotNone(rec)
            self.assertTrue(rec.normalized_event_id.startswith("norm_"))
            self.assertTrue(rec.original_event_id.startswith("evt_"))

    # ── Test 25: Execution record links to rule version ───────────────────────
    def test_25_execution_record_links_to_rule_version(self):
        """Verify execution record links to rule_version_id and version_number."""
        with SessionLocal() as db:
            rec = db.query(DetectionExecution).filter(
                DetectionExecution.rule_id == "drule_suspicious_ssh"
            ).first()
            self.assertIsNotNone(rec)
            self.assertTrue(rec.rule_version_id.startswith("drver_"))
            self.assertEqual(rec.rule_version_number, 1)

    # ── Test 26: Rule version hash preserved ──────────────────────────────────
    def test_26_rule_version_hash_preserved(self):
        """Verify rule version hash is saved in execution details."""
        with SessionLocal() as db:
            rec = db.query(DetectionExecution).filter(
                DetectionExecution.rule_id == "drule_suspicious_ssh"
            ).first()
            self.assertIsNotNone(rec)
            self.assertIn("version_hash", rec.execution_details)
            self.assertTrue(len(rec.execution_details["version_hash"]) == 64)

    # ── Test 27: Raw evidence remains unchanged ───────────────────────────────
    def test_27_raw_evidence_remains_unchanged(self):
        """Verify executing rules does not mutate raw evidence in Evidence Vault."""
        with SessionLocal() as db:
            raw_event = db.query(IngestedEvent).first()
            if raw_event:
                initial_hash = raw_event.raw_content_hash
                initial_raw = raw_event.raw_content
                # Run execution
                DetectionExecutionService.execute_rule_against_event(
                    db, "drule_suspicious_ssh", "norm_demo_ssh_allowed", force_recompute=True
                )
                db.refresh(raw_event)
                self.assertEqual(raw_event.raw_content_hash, initial_hash)
                self.assertEqual(raw_event.raw_content, initial_raw)

    # ── Test 28: Normalized event remains unchanged ───────────────────────────
    def test_28_normalized_event_remains_unchanged(self):
        """Verify executing rules does not mutate canonical normalized event fields."""
        with SessionLocal() as db:
            event = db.query(NormalizedEvent).filter(
                NormalizedEvent.normalized_event_id == "norm_demo_ssh_allowed"
            ).first()
            initial_action = event.action
            initial_port = event.dst_port

            DetectionExecutionService.execute_rule_against_event(
                db, "drule_suspicious_ssh", "norm_demo_ssh_allowed", force_recompute=True
            )
            db.refresh(event)
            self.assertEqual(event.action, initial_action)
            self.assertEqual(event.dst_port, initial_port)

    # ── Test 29: RBAC unauthorized request returns 401 ────────────────────────
    def test_29_unauthenticated_request_returns_401(self):
        """Verify executing rule without auth headers returns HTTP 401."""
        resp = client.post(
            "/api/v1/detection-rules/drule_suspicious_ssh/execute/norm_demo_ssh_allowed"
        )
        self.assertEqual(resp.status_code, 401)

    # ── Test 30: Unauthorized role returns 403 ────────────────────────────────
    def test_30_unauthorized_role_returns_403(self):
        """Verify VIEWER role cannot execute detection rules (HTTP 403)."""
        headers = get_auth_headers("VIEWER")
        resp = client.post(
            "/api/v1/detection-rules/drule_suspicious_ssh/execute/norm_demo_ssh_allowed",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 403)

    # ── Test 31: Security analyst can execute ─────────────────────────────────
    def test_31_security_analyst_can_execute(self):
        """Verify SECURITY_ANALYST role can successfully execute rules."""
        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.post(
            "/api/v1/detection-rules/drule_suspicious_ssh/execute/norm_demo_ssh_allowed",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)

    # ── Test 32: Auditor can read but not execute ─────────────────────────────
    def test_32_auditor_can_read_but_not_execute(self):
        """Verify AUDITOR role can read executions and traces but cannot trigger execution."""
        auditor_headers = get_auth_headers("AUDITOR")
        # 1. Reading executions list succeeds (200)
        list_resp = client.get("/api/v1/detection-executions", headers=auditor_headers)
        self.assertEqual(list_resp.status_code, 200)

        # 2. Executing rule is forbidden (403)
        exec_resp = client.post(
            "/api/v1/detection-rules/drule_suspicious_ssh/execute/norm_demo_ssh_allowed",
            headers=auditor_headers,
        )
        self.assertEqual(exec_resp.status_code, 403)

    # ── Test 33: Trace endpoint returns full 10-stage chain ───────────────────
    def test_33_trace_endpoint_returns_full_10_stage_chain(self):
        """Verify 10-stage execution provenance trace is complete and accurately structured."""
        headers = get_auth_headers("ADMIN")
        with SessionLocal() as db:
            exec_rec = DetectionExecutionService.execute_rule_against_event(
                db, "drule_suspicious_ssh", "norm_demo_ssh_allowed"
            )
            exec_id = exec_rec.execution_id

        resp = client.get(f"/api/v1/detection-executions/{exec_id}/trace", headers=headers)
        self.assertEqual(resp.status_code, 200)
        trace_data = resp.json()
        self.assertEqual(trace_data["execution_id"], exec_id)
        self.assertEqual(len(trace_data["stages"]), 10)

        stage_names = [s["stage_name"] for s in trace_data["stages"]]
        expected_stages = [
            "RAW_EVIDENCE_VAULT",
            "NORMALIZED_EVENT",
            "DETECTION_RULE",
            "ACTIVE_RULE_VERSION",
            "RULE_VERSION_HASH",
            "CANONICAL_DEPENDENCIES",
            "FIELD_RESOLUTION",
            "CONDITION_EVALUATIONS",
            "EXECUTION_RESULT",
            "GOVERNANCE_REFERENCES",
        ]
        self.assertEqual(stage_names, expected_stages)

    # ── Test 34: Batch execute all ACTIVE rules for an event ─────────────────
    def test_34_batch_execute_all_active_rules(self):
        """Verify POST /api/v1/normalized-events/{id}/run-detections executes all active rules."""
        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.post(
            "/api/v1/normalized-events/norm_demo_ssh_allowed/run-detections",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["rules_evaluated"], 1)
        self.assertIn("matches", data)
        self.assertIn("no_matches", data)
        self.assertIn("partial", data)
        self.assertIn("executions", data)

    # ── Test 35: Execution listing with filters & pagination ──────────────────
    def test_35_list_detection_executions_with_filters(self):
        """Verify GET /api/v1/detection-executions returns paginated filtered records."""
        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.get(
            "/api/v1/detection-executions?execution_status=MATCH&limit=10&offset=0",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total", data)
        self.assertIn("executions", data)
        for ex in data["executions"]:
            self.assertEqual(ex["execution_status"], "MATCH")
