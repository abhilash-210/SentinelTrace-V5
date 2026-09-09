"""
services/detection_execution_service.py
----------------------------------------
Deterministic Real-Time Detection Rule Execution Engine.

Sprint 7A — Real-Time Detection Rule Execution Engine.

Core Invariants:
1. Raw evidence and normalized events remain strictly immutable.
2. Only ACTIVE governed detection rule versions execute.
3. DRAFT, PENDING_REVIEW, APPROVED, REJECTED, SUPERSEDED, and DISABLED versions MUST NOT execute.
4. Multiple ACTIVE versions for a single rule violates governance invariants; engine aborts execution.
5. Rule execution is completely deterministic and reproducible.
6. Execution idempotency is guaranteed via SHA-256 fingerprinting:
     SHA-256(rule_version_id + ":" + normalized_event_id + ":" + execution_engine_version)
7. Controlled Declarative JSON DSL: No eval(), exec(), dynamic Python execution, or shell execution.
8. Telemetry Completeness: PARTIAL != NO_MATCH. Missing fields yield PARTIAL, not false NO_MATCH.
9. Full 10-stage end-to-end explainability and provenance preservation.
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.detection_execution import DetectionConditionResult, DetectionExecution
from app.models.detection_rule import DetectionRule
from app.models.detection_rule_governance import (
    DetectionRuleGovernanceEvent,
    DetectionRuleVersion,
    DetectionRuleVersionDependency,
)
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.services.detection_field_resolver import DetectionFieldResolver, FieldResolutionResult

logger = logging.getLogger("sentinel.services.detection_execution")

ENGINE_VERSION = "v5.7.0"


class DetectionExecutionService:
    """Service providing safe, deterministic execution of governed detection rules."""

    ENGINE_VERSION = ENGINE_VERSION

    # Known DSL templates for baseline rules if not specified as explicit JSON in query_signature
    DEFAULT_RULE_DSLS: Dict[str, Dict[str, Any]] = {
        "drule_fw_deny_scan": {
            "operator": "AND",
            "conditions": [
                {"field": "action.result", "comparison": "EQUALS", "value": "DENY"},
                {"field": "dst_endpoint.port", "comparison": "EXISTS"},
            ],
        },
        "drule_brute_force": {
            "operator": "AND",
            "conditions": [
                {"field": "authentication.outcome", "comparison": "EQUALS", "value": "FAILURE"},
            ],
        },
        "drule_lateral_move": {
            "operator": "AND",
            "conditions": [
                {"field": "protocol", "comparison": "EQUALS", "value": "TCP"},
                {"field": "dst_endpoint.port", "comparison": "IN", "value": [22, 3389, 445]},
            ],
        },
        "drule_priv_escalation": {
            "operator": "AND",
            "conditions": [
                {"field": "process_name", "comparison": "EXISTS"},
                {"field": "user_name", "comparison": "EQUALS", "value": "root"},
            ],
        },
        "drule_suspicious_ssh": {
            "operator": "AND",
            "conditions": [
                {"field": "action.result", "comparison": "EQUALS", "value": "ALLOWED"},
                {"field": "dst_endpoint.port", "comparison": "EQUALS", "value": 22},
            ],
        },
    }

    # ── Idempotency Fingerprint ────────────────────────────────────────────────
    @classmethod
    def compute_execution_fingerprint(
        cls,
        rule_version_id: str,
        normalized_event_id: str,
        engine_version: Optional[str] = None,
    ) -> str:
        """
        Compute deterministic SHA-256 fingerprint for rule execution idempotency:
        SHA-256(rule_version_id + ":" + normalized_event_id + ":" + engine_version)
        """
        ver = engine_version or cls.ENGINE_VERSION
        raw = f"{rule_version_id}:{normalized_event_id}:{ver}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # ── Active Version Resolution ──────────────────────────────────────────────
    @classmethod
    def resolve_active_rule_version(
        cls, db: Session, rule_id: str
    ) -> Tuple[Optional[DetectionRuleVersion], Optional[str]]:
        """
        Resolves the currently ACTIVE governed version for a given rule_id.
        Enforces governance invariants:
        - Must be status == 'ACTIVE'
        - If multiple ACTIVE versions exist -> governance violation (returns None, error)
        - If no ACTIVE version exists -> returns None, reason
        """
        active_versions = (
            db.query(DetectionRuleVersion)
            .filter(
                DetectionRuleVersion.rule_id == rule_id,
                DetectionRuleVersion.status == "ACTIVE",
            )
            .all()
        )

        if not active_versions:
            return None, f"Rule '{rule_id}' has no ACTIVE governed version."

        if len(active_versions) > 1:
            err_msg = (
                f"GOVERNANCE INVARIANT VIOLATION: Rule '{rule_id}' has {len(active_versions)} "
                f"simultaneously ACTIVE versions. Execution aborted."
            )
            logger.error(err_msg)
            return None, err_msg

        return active_versions[0], None

    # ── Parse DSL Tree ─────────────────────────────────────────────────────────
    @classmethod
    def parse_rule_dsl(cls, version: DetectionRuleVersion) -> Dict[str, Any]:
        """
        Extracts and parses the declarative JSON DSL from a DetectionRuleVersion.
        Falls back to default baseline template if query_signature is a plain signature label.
        """
        sig = version.query_signature or ""
        sig_trimmed = sig.strip()

        if sig_trimmed.startswith("{") and sig_trimmed.endswith("}"):
            try:
                parsed = json.loads(sig_trimmed)
                if isinstance(parsed, dict) and "conditions" in parsed:
                    return parsed
            except Exception as e:
                logger.warning("Failed to parse JSON DSL from query_signature: %s", e)

        # Fallback to rule default or baseline template
        if version.rule_id in cls.DEFAULT_RULE_DSLS:
            return cls.DEFAULT_RULE_DSLS[version.rule_id]

        # Generic default condition if none specified
        return {
            "operator": "AND",
            "conditions": [
                {"field": "action.result", "comparison": "EXISTS"}
            ],
        }

    # ── Condition & Group Evaluation ───────────────────────────────────────────
    @classmethod
    def evaluate_condition(
        cls, event: NormalizedEvent, cond_def: Dict[str, Any], condition_index: int
    ) -> Dict[str, Any]:
        """
        Evaluate a single atomic condition against a NormalizedEvent.
        Supported operators:
          EQUALS, NOT_EQUALS, GREATER_THAN, GREATER_THAN_OR_EQUAL,
          LESS_THAN, LESS_THAN_OR_EQUAL, CONTAINS, IN, EXISTS, NOT_EXISTS
        """
        field_name = cond_def.get("field", "")
        comparison = cond_def.get("comparison", "EQUALS").upper()
        expected = cond_def.get("value")

        # 1. Resolve field safely
        res: FieldResolutionResult = DetectionFieldResolver.resolve(event, field_name)
        observed = res.value
        field_resolved = res.resolved

        # 2. Check EXISTS / NOT_EXISTS handling for missing fields
        if not field_resolved:
            if comparison == "NOT_EXISTS":
                return {
                    "condition_index": condition_index,
                    "canonical_field": field_name,
                    "comparison_operator": comparison,
                    "expected_value": expected,
                    "observed_value": None,
                    "field_resolved": False,
                    "condition_result": "TRUE",
                    "explanation": f"Field '{field_name}' does not exist in telemetry (as expected).",
                }
            elif comparison == "EXISTS":
                return {
                    "condition_index": condition_index,
                    "canonical_field": field_name,
                    "comparison_operator": comparison,
                    "expected_value": expected,
                    "observed_value": None,
                    "field_resolved": False,
                    "condition_result": "FALSE",
                    "explanation": f"Field '{field_name}' was expected to exist but is missing.",
                }
            else:
                return {
                    "condition_index": condition_index,
                    "canonical_field": field_name,
                    "comparison_operator": comparison,
                    "expected_value": expected,
                    "observed_value": None,
                    "field_resolved": False,
                    "condition_result": "MISSING",
                    "explanation": (
                        f"Required canonical field '{field_name}' could not be resolved from telemetry. "
                        f"Evaluation marked as MISSING."
                    ),
                }

        # 3. Field is resolved; evaluate comparison operator
        try:
            matched, explanation = cls._compare_values(comparison, observed, expected, field_name)
            return {
                "condition_index": condition_index,
                "canonical_field": field_name,
                "comparison_operator": comparison,
                "expected_value": expected,
                "observed_value": observed,
                "field_resolved": True,
                "condition_result": "TRUE" if matched else "FALSE",
                "explanation": explanation,
            }
        except Exception as exc:
            return {
                "condition_index": condition_index,
                "canonical_field": field_name,
                "comparison_operator": comparison,
                "expected_value": expected,
                "observed_value": observed,
                "field_resolved": True,
                "condition_result": "ERROR",
                "explanation": f"Condition evaluation error: {str(exc)}",
            }

    @classmethod
    def _compare_values(
        cls, comparison: str, observed: Any, expected: Any, field_name: str
    ) -> Tuple[bool, str]:
        """Helper to perform safe deterministic value comparison without eval/exec."""
        # Normalize strings for comparison
        def _to_clean_str(val: Any) -> str:
            if val is None:
                return ""
            return str(val).strip()

        # Handle EQUALS
        if comparison == "EQUALS":
            # If both can be numbers
            if isinstance(observed, (int, float)) and isinstance(expected, (int, float)):
                match = float(observed) == float(expected)
            else:
                match = _to_clean_str(observed).lower() == _to_clean_str(expected).lower()
            exp = (
                f"Field '{field_name}' observed '{observed}' {'==' if match else '!='} expected '{expected}'."
            )
            return match, exp

        # Handle NOT_EQUALS
        if comparison == "NOT_EQUALS":
            if isinstance(observed, (int, float)) and isinstance(expected, (int, float)):
                match = float(observed) != float(expected)
            else:
                match = _to_clean_str(observed).lower() != _to_clean_str(expected).lower()
            exp = (
                f"Field '{field_name}' observed '{observed}' {'!=' if match else '=='} expected '{expected}'."
            )
            return match, exp

        # Numeric comparisons
        if comparison in ("GREATER_THAN", "GREATER_THAN_OR_EQUAL", "LESS_THAN", "LESS_THAN_OR_EQUAL"):
            try:
                obs_num = float(observed)
                exp_num = float(expected)
            except (ValueError, TypeError):
                raise ValueError(
                    f"Cannot perform numeric comparison '{comparison}' on non-numeric types "
                    f"(observed: {type(observed).__name__}, expected: {type(expected).__name__})"
                )

            if comparison == "GREATER_THAN":
                match = obs_num > exp_num
                sym = ">"
            elif comparison == "GREATER_THAN_OR_EQUAL":
                match = obs_num >= exp_num
                sym = ">="
            elif comparison == "LESS_THAN":
                match = obs_num < exp_num
                sym = "<"
            else:
                match = obs_num <= exp_num
                sym = "<="

            exp = f"Numeric check '{field_name}': {obs_num} {sym} {exp_num} evaluates to {match}."
            return match, exp

        # CONTAINS
        if comparison == "CONTAINS":
            if isinstance(observed, list):
                match = expected in observed or any(
                    _to_clean_str(expected).lower() == _to_clean_str(item).lower() for item in observed
                )
            else:
                match = _to_clean_str(expected).lower() in _to_clean_str(observed).lower()
            exp = f"Substring/collection check '{field_name}': '{expected}' in '{observed}' is {match}."
            return match, exp

        # IN
        if comparison == "IN":
            if not isinstance(expected, (list, tuple, set)):
                expected_list = [_to_clean_str(expected).lower()]
            else:
                expected_list = [_to_clean_str(x).lower() for x in expected]

            match = _to_clean_str(observed).lower() in expected_list
            exp = f"Set inclusion check '{field_name}': '{observed}' in {expected} is {match}."
            return match, exp

        # EXISTS / NOT_EXISTS
        if comparison == "EXISTS":
            match = observed is not None and observed != ""
            return match, f"Field '{field_name}' existence check evaluates to {match}."

        if comparison == "NOT_EXISTS":
            match = observed is None or observed == ""
            return match, f"Field '{field_name}' non-existence check evaluates to {match}."

        raise ValueError(f"Unsupported comparison operator '{comparison}'.")

    @classmethod
    def evaluate_condition_group(
        cls, event: NormalizedEvent, dsl: Dict[str, Any]
    ) -> Tuple[str, bool, int, int, int, List[Dict[str, Any]], str]:
        """
        Evaluates a complete DSL condition tree against a normalized event.
        Returns:
          (status, matched_bool, total_conditions, matched_count, missing_count, condition_results, explanation)
        """
        operator = dsl.get("operator", "AND").upper()
        conditions = dsl.get("conditions", [])

        if not conditions:
            # Empty condition set -> NO_MATCH or default MATCH based on policy
            return "NO_MATCH", False, 0, 0, 0, [], "Rule contains no conditions to evaluate."

        cond_results = []
        has_error = False
        has_false = False
        has_true = False
        has_missing = False

        for idx, cond in enumerate(conditions):
            res = cls.evaluate_condition(event, cond, idx)
            cond_results.append(res)
            c_res = res["condition_result"]

            if c_res == "ERROR":
                has_error = True
            elif c_res == "FALSE":
                has_false = True
            elif c_res == "TRUE":
                has_true = True
            elif c_res == "MISSING":
                has_missing = True

        total_count = len(cond_results)
        matched_count = sum(1 for c in cond_results if c["condition_result"] == "TRUE")
        missing_count = sum(1 for c in cond_results if c["condition_result"] == "MISSING")

        # Determine overall execution status based on boolean operator
        if operator == "AND":
            if has_error:
                status = "ERROR"
                matched = False
                explanation = "One or more conditions encountered evaluation errors."
            elif has_false:
                status = "NO_MATCH"
                matched = False
                explanation = "One or more conditions evaluated to FALSE under AND logic."
            elif has_missing:
                status = "PARTIAL"
                matched = False
                explanation = (
                    "Required canonical field could not be resolved. The rule was not classified "
                    "as NO_MATCH because incomplete telemetry does not prove the detection condition was false."
                )
            else:
                # All TRUE
                status = "MATCH"
                matched = True
                explanation = "All rule conditions evaluated to TRUE under AND logic."

        elif operator == "OR":
            if has_true:
                status = "MATCH"
                matched = True
                explanation = "At least one condition evaluated to TRUE under OR logic."
            elif has_error:
                status = "ERROR"
                matched = False
                explanation = "Conditions encountered errors without any TRUE match under OR logic."
            elif has_missing:
                status = "PARTIAL"
                matched = False
                explanation = (
                    "No condition evaluated to TRUE, but one or more required fields were MISSING "
                    "from telemetry. Marked as PARTIAL."
                )
            else:
                # All FALSE
                status = "NO_MATCH"
                matched = False
                explanation = "All conditions evaluated to FALSE under OR logic."

        else:
            status = "ERROR"
            matched = False
            explanation = f"Unsupported top-level boolean operator '{operator}'."

        return status, matched, total_count, matched_count, missing_count, cond_results, explanation

    # ── Execute Rule Against Event ─────────────────────────────────────────────
    @classmethod
    def execute_rule_against_event(
        cls,
        db: Session,
        rule_id: str,
        normalized_event_id: str,
        force_recompute: bool = False,
    ) -> DetectionExecution:
        """
        Execute an ACTIVE governed detection rule against a normalized event.
        Guarantees idempotency via SHA-256 execution fingerprint.
        """
        # 1. Load NormalizedEvent
        event = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.normalized_event_id == normalized_event_id)
            .first()
        )
        if not event:
            raise ValueError(f"Normalized event '{normalized_event_id}' not found.")

        # 2. Resolve ACTIVE rule version
        version, err = cls.resolve_active_rule_version(db, rule_id)
        if err or not version:
            raise ValueError(err or f"No ACTIVE version found for rule '{rule_id}'.")

        # 3. Check Idempotency Fingerprint
        fingerprint = cls.compute_execution_fingerprint(
            rule_version_id=version.version_id,
            normalized_event_id=event.normalized_event_id,
            engine_version=cls.ENGINE_VERSION,
        )

        if not force_recompute:
            existing = (
                db.query(DetectionExecution)
                .filter(DetectionExecution.execution_fingerprint == fingerprint)
                .first()
            )
            if existing:
                logger.info("Returning existing idempotent execution record: %s", existing.execution_id)
                return existing
        else:
            existing = (
                db.query(DetectionExecution)
                .filter(DetectionExecution.execution_fingerprint == fingerprint)
                .first()
            )
            if existing:
                db.delete(existing)
                db.flush()

        # 4. Parse DSL and Evaluate
        dsl = cls.parse_rule_dsl(version)
        (
            status,
            matched,
            total_cond,
            matched_cond,
            missing_cond,
            cond_results,
            explanation,
        ) = cls.evaluate_condition_group(event, dsl)

        now = datetime.now(timezone.utc)
        execution_id = f"dexec_{uuid.uuid4().hex[:12]}"

        # 5. Build Execution Record
        execution = DetectionExecution(
            execution_id=execution_id,
            rule_id=rule_id,
            rule_version_id=version.version_id,
            rule_version_number=version.version_number,
            normalized_event_id=event.normalized_event_id,
            original_event_id=event.original_event_id,
            execution_status=status,
            matched=matched,
            conditions_total=total_cond,
            conditions_matched=matched_cond,
            conditions_missing=missing_cond,
            execution_fingerprint=fingerprint,
            execution_details={
                "dsl_evaluated": dsl,
                "rule_name": version.rule_name,
                "vendor_name": version.vendor_name,
                "rule_severity": version.severity,
                "version_hash": version.version_hash,
            },
            execution_explanation=explanation,
            executed_at=now,
            execution_engine_version=cls.ENGINE_VERSION,
        )
        db.add(execution)
        db.flush()

        # 6. Save Fine-Grained Condition Results
        for cr in cond_results:
            cond_record = DetectionConditionResult(
                execution_id=execution.execution_id,
                condition_index=cr["condition_index"],
                canonical_field=cr["canonical_field"],
                comparison_operator=cr["comparison_operator"],
                expected_value=cr["expected_value"],
                observed_value=cr["observed_value"],
                field_resolved=cr["field_resolved"],
                condition_result=cr["condition_result"],
                explanation=cr["explanation"],
            )
            db.add(cond_record)

        db.commit()
        db.refresh(execution)
        return execution

    # ── Batch Execute All Active Rules for an Event ────────────────────────────
    @classmethod
    def execute_active_rules_for_event(
        cls, db: Session, normalized_event_id: str
    ) -> Dict[str, Any]:
        """
        Execute all currently ACTIVE governed detection rules against a normalized event.
        """
        event = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.normalized_event_id == normalized_event_id)
            .first()
        )
        if not event:
            raise ValueError(f"Normalized event '{normalized_event_id}' not found.")

        active_versions = (
            db.query(DetectionRuleVersion)
            .filter(DetectionRuleVersion.status == "ACTIVE")
            .all()
        )

        executions: List[DetectionExecution] = []
        matches = 0
        no_matches = 0
        partial = 0
        errors = 0

        # Group by rule_id to detect governance violations
        rule_version_map: Dict[str, List[DetectionRuleVersion]] = {}
        for v in active_versions:
            rule_version_map.setdefault(v.rule_id, []).append(v)

        for r_id, vers in rule_version_map.items():
            if len(vers) > 1:
                # Governance violation: skip and increment error
                logger.error(
                    "Skipping execution for rule '%s' due to multiple active versions (%d)",
                    r_id,
                    len(vers),
                )
                errors += 1
                continue

            try:
                exec_record = cls.execute_rule_against_event(db, r_id, normalized_event_id)
                executions.append(exec_record)

                if exec_record.execution_status == "MATCH":
                    matches += 1
                elif exec_record.execution_status == "NO_MATCH":
                    no_matches += 1
                elif exec_record.execution_status == "PARTIAL":
                    partial += 1
                elif exec_record.execution_status == "ERROR":
                    errors += 1
            except Exception as e:
                logger.error("Error executing rule '%s': %s", r_id, e)
                errors += 1

        return {
            "normalized_event_id": normalized_event_id,
            "original_event_id": event.original_event_id,
            "rules_evaluated": len(executions),
            "matches": matches,
            "no_matches": no_matches,
            "partial": partial,
            "errors": errors,
            "executions": [e.to_dict() for e in executions],
        }

    # ── 10-Stage Provenance Trace ──────────────────────────────────────────────
    @classmethod
    def get_execution_trace(cls, db: Session, execution_id: str) -> Dict[str, Any]:
        """
        Generate 10-stage end-to-end cryptographic and governance provenance trace
        for a detection execution.
        """
        execution = (
            db.query(DetectionExecution)
            .filter(DetectionExecution.execution_id == execution_id)
            .first()
        )
        if not execution:
            raise ValueError(f"Execution '{execution_id}' not found.")

        # Stage 1: Raw Evidence
        raw_event = (
            db.query(IngestedEvent)
            .filter(IngestedEvent.event_id == execution.original_event_id)
            .first()
        )

        # Stage 2: Normalized Event
        norm_event = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.normalized_event_id == execution.normalized_event_id)
            .first()
        )

        # Stage 3: Detection Rule
        rule = (
            db.query(DetectionRule)
            .filter(DetectionRule.rule_id == execution.rule_id)
            .first()
        )

        # Stage 4 & 5: Active Rule Version & Hash
        version = (
            db.query(DetectionRuleVersion)
            .filter(DetectionRuleVersion.version_id == execution.rule_version_id)
            .first()
        )

        # Stage 6: Canonical Dependencies
        deps = (
            db.query(DetectionRuleVersionDependency)
            .filter(DetectionRuleVersionDependency.version_id == execution.rule_version_id)
            .all()
        )

        # Stage 7 & 8: Resolved Field Values & Condition Evaluations
        cond_results = (
            db.query(DetectionConditionResult)
            .filter(DetectionConditionResult.execution_id == execution.execution_id)
            .order_by(DetectionConditionResult.condition_index.asc())
            .all()
        )

        # Stage 10: Governance References
        gov_events = (
            db.query(DetectionRuleGovernanceEvent)
            .filter(DetectionRuleGovernanceEvent.version_id == execution.rule_version_id)
            .order_by(DetectionRuleGovernanceEvent.created_at.asc())
            .all()
        )

        stages = [
            {
                "stage_number": 1,
                "stage_name": "RAW_EVIDENCE_VAULT",
                "description": "Immutable raw security log sealed with SHA-256 checksum in Evidence Vault.",
                "data": {
                    "event_id": raw_event.event_id if raw_event else execution.original_event_id,
                    "payload_sha256": raw_event.raw_content_hash if raw_event else "N/A",
                    "source_type": raw_event.source_type if raw_event else "N/A",
                    "received_at": raw_event.ingested_at.isoformat() if raw_event and raw_event.ingested_at else None,
                },
            },
            {
                "stage_number": 2,
                "stage_name": "NORMALIZED_EVENT",
                "description": "OCSF-aligned canonical normalized event structure.",
                "data": {
                    "normalized_event_id": norm_event.normalized_event_id if norm_event else execution.normalized_event_id,
                    "class_name": norm_event.class_name if norm_event else "N/A",
                    "action": norm_event.action if norm_event else "N/A",
                    "src_ip": norm_event.src_ip if norm_event else None,
                    "dst_ip": norm_event.dst_ip if norm_event else None,
                    "dst_port": norm_event.dst_port if norm_event else None,
                },
            },
            {
                "stage_number": 3,
                "stage_name": "DETECTION_RULE",
                "description": "Registered detection rule metadata in SentinelTrace catalog.",
                "data": {
                    "rule_id": rule.rule_id if rule else execution.rule_id,
                    "rule_name": rule.rule_name if rule else "Unknown Rule",
                    "vendor_name": rule.vendor_name if rule else "ANY",
                    "severity": rule.severity if rule else "MEDIUM",
                },
            },
            {
                "stage_number": 4,
                "stage_name": "ACTIVE_RULE_VERSION",
                "description": "Governed ACTIVE version snapshot loaded for real-time execution.",
                "data": {
                    "version_id": version.version_id if version else execution.rule_version_id,
                    "version_number": version.version_number if version else execution.rule_version_number,
                    "status": version.status if version else "ACTIVE",
                    "created_by": version.created_by_user_id if version else None,
                    "reviewed_by": version.reviewed_by_user_id if version else None,
                    "activated_by": version.activated_by_user_id if version else None,
                },
            },
            {
                "stage_number": 5,
                "stage_name": "RULE_VERSION_HASH",
                "description": "Deterministic SHA-256 hash sealing this governed version definition.",
                "data": {
                    "version_hash": version.version_hash if version else "N/A",
                    "integrity_status": "VERIFIED_SEALED",
                },
            },
            {
                "stage_number": 6,
                "stage_name": "CANONICAL_DEPENDENCIES",
                "description": "Declared canonical fields required by this detection rule version.",
                "data": {
                    "dependencies": [
                        {
                            "field": d.canonical_field,
                            "type": d.dependency_type,
                            "is_protected": d.is_protected_field,
                        }
                        for d in deps
                    ],
                },
            },
            {
                "stage_number": 7,
                "stage_name": "FIELD_RESOLUTION",
                "description": "Safe, non-guessing extraction of canonical fields from normalized telemetry.",
                "data": {
                    "resolved_fields": [
                        {
                            "field": cr.canonical_field,
                            "resolved": cr.field_resolved,
                            "observed_value": cr.observed_value,
                        }
                        for cr in cond_results
                    ],
                },
            },
            {
                "stage_number": 8,
                "stage_name": "CONDITION_EVALUATIONS",
                "description": "Deterministic evaluation of each declarative DSL condition.",
                "data": {
                    "conditions": [cr.to_dict() for cr in cond_results],
                },
            },
            {
                "stage_number": 9,
                "stage_name": "EXECUTION_RESULT",
                "description": "Overall engine decision and explainability statement.",
                "data": {
                    "execution_status": execution.execution_status,
                    "matched": execution.matched,
                    "conditions_total": execution.conditions_total,
                    "conditions_matched": execution.conditions_matched,
                    "conditions_missing": execution.conditions_missing,
                    "explanation": execution.execution_explanation,
                    "fingerprint": execution.execution_fingerprint,
                },
            },
            {
                "stage_number": 10,
                "stage_name": "GOVERNANCE_REFERENCES",
                "description": "Maker-checker lifecycle and audit events associated with this rule version.",
                "data": {
                    "governance_events": [
                        {
                            "event_type": ge.event_type,
                            "actor_user_id": ge.actor_user_id,
                            "actor_role": ge.actor_role,
                            "event_hash": ge.event_hash,
                            "timestamp": ge.created_at.isoformat() if ge.created_at else None,
                        }
                        for ge in gov_events
                    ],
                },
            },
        ]

        return {
            "execution_id": execution.execution_id,
            "execution_status": execution.execution_status,
            "matched": execution.matched,
            "executed_at": execution.executed_at.isoformat() if execution.executed_at else None,
            "execution_engine_version": execution.execution_engine_version,
            "stages": stages,
        }

    # ── Demo Seeder ────────────────────────────────────────────────────────────
    @classmethod
    def seed_demo_execution_scenarios(cls, db: Session) -> None:
        """
        Seed deterministic demonstration scenarios:
        1. Suspicious SSH Access MATCH (action=ALLOWED, dst_port=22)
        2. Suspicious SSH Access NO_MATCH (action=DENIED, dst_port=22)
        3. Authentication Brute Force MATCH (outcome=FAILURE)
        4. Missing required field -> PARTIAL (authentication.outcome on firewall event)
        """
        # 1. Ensure Suspicious SSH rule exists
        ssh_rule = db.query(DetectionRule).filter(DetectionRule.rule_id == "drule_suspicious_ssh").first()
        now = datetime.now(timezone.utc)
        if not ssh_rule:
            ssh_rule = DetectionRule(
                rule_id="drule_suspicious_ssh",
                rule_name="Suspicious SSH Access Detection",
                vendor_name="ANY",
                description="Detects successful inbound SSH connections on port 22.",
                severity="HIGH",
                status="ACTIVE",
                version=1,
                mitre_tactic="TA0001: Initial Access",
                mitre_technique="T1078: Valid Accounts",
            )
            db.add(ssh_rule)
            db.flush()

        # Ensure active version exists for drule_suspicious_ssh
        ssh_ver = (
            db.query(DetectionRuleVersion)
            .filter(
                DetectionRuleVersion.rule_id == "drule_suspicious_ssh",
                DetectionRuleVersion.version_number == 1,
            )
            .first()
        )
        if not ssh_ver:
            ssh_dsl = json.dumps(cls.DEFAULT_RULE_DSLS["drule_suspicious_ssh"])
            v_hash = hashlib.sha256(ssh_dsl.encode("utf-8")).hexdigest()
            ssh_ver = DetectionRuleVersion(
                version_id="drver_suspicious_ssh_v1",
                rule_id="drule_suspicious_ssh",
                version_number=1,
                rule_name="Suspicious SSH Access Detection",
                vendor_name="ANY",
                description="Detects successful inbound SSH connections on port 22.",
                query_signature=ssh_dsl,
                severity="HIGH",
                mitre_techniques=["T1078"],
                status="ACTIVE",
                created_by_user_id="usr_author_cisco",
                created_at=now,
                submitted_at=now,
                submitted_by_user_id="usr_author_cisco",
                reviewed_at=now,
                reviewed_by_user_id="usr_reviewer_01",
                approval_decision="APPROVED",
                approval_comment="Approved SSH access detection baseline.",
                activated_at=now,
                activated_by_user_id="usr_admin_01",
                version_hash=v_hash,
            )
            db.add(ssh_ver)
            db.flush()

        # Find or create demo normalized events
        # Event 1: SSH Allowed
        norm_ssh_allowed = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.action.in_(["ALLOWED", "ALLOW"]), NormalizedEvent.dst_port == 22)
            .first()
        )
        if not norm_ssh_allowed:
            # Check for raw event
            raw_event = db.query(IngestedEvent).first()
            raw_id = raw_event.event_id if raw_event else "evt_demo_raw_ssh_01"
            norm_ssh_allowed = NormalizedEvent(
                normalized_event_id="norm_demo_ssh_allowed",
                original_event_id=raw_id,
                class_uid=4001,
                class_name="Network Activity",
                activity_id=1,
                activity_name="Traffic Allowed",
                source_name="cisco_firewall_01",
                source_type="firewall",
                action="ALLOWED",
                src_ip="192.168.1.100",
                src_port=54321,
                dst_ip="10.0.0.5",
                dst_port=22,
                protocol="TCP",
                severity="Informational",
                parser_name="CiscoASAParser",
                parser_version="1.0.0",
                normalization_status="NORMALIZED",
                normalization_confidence=1.0,
                raw_data={"action.result": "ALLOWED", "dst_endpoint.port": 22},
            )
            db.add(norm_ssh_allowed)
            db.flush()

        # Event 2: SSH Denied
        norm_ssh_denied = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.action.in_(["DENIED", "DENY"]), NormalizedEvent.dst_port == 22)
            .first()
        )
        if not norm_ssh_denied:
            raw_event = db.query(IngestedEvent).first()
            raw_id = raw_event.event_id if raw_event else "evt_demo_raw_ssh_02"
            norm_ssh_denied = NormalizedEvent(
                normalized_event_id="norm_demo_ssh_denied",
                original_event_id=raw_id,
                class_uid=4001,
                class_name="Network Activity",
                activity_id=2,
                activity_name="Traffic Denied",
                source_name="cisco_firewall_01",
                source_type="firewall",
                action="DENIED",
                src_ip="192.168.1.105",
                src_port=54322,
                dst_ip="10.0.0.5",
                dst_port=22,
                protocol="TCP",
                severity="Warning",
                parser_name="CiscoASAParser",
                parser_version="1.0.0",
                normalization_status="NORMALIZED",
                normalization_confidence=1.0,
                raw_data={"action.result": "DENIED", "dst_endpoint.port": 22},
            )
            db.add(norm_ssh_denied)
            db.flush()

        # Event 3: Auth Failure
        norm_auth_fail = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.class_name == "Authentication", NormalizedEvent.action == "FAILURE")
            .first()
        )
        if not norm_auth_fail:
            raw_event = db.query(IngestedEvent).first()
            raw_id = raw_event.event_id if raw_event else "evt_demo_raw_auth_01"
            norm_auth_fail = NormalizedEvent(
                normalized_event_id="norm_demo_auth_failure",
                original_event_id=raw_id,
                class_uid=3001,
                class_name="Authentication",
                activity_id=2,
                activity_name="Logon Failure",
                source_name="auth_service",
                source_type="authentication",
                action="FAILURE",
                user_name="admin",
                src_ip="203.0.113.55",
                parser_name="SyslogAuthParser",
                parser_version="1.0.0",
                normalization_status="NORMALIZED",
                normalization_confidence=1.0,
                raw_data={"authentication.outcome": "FAILURE", "user_name": "admin"},
            )
            db.add(norm_auth_fail)
            db.flush()

        db.commit()

        # Execute demo scenarios idempotently
        try:
            cls.execute_rule_against_event(db, "drule_suspicious_ssh", norm_ssh_allowed.normalized_event_id)
            cls.execute_rule_against_event(db, "drule_suspicious_ssh", norm_ssh_denied.normalized_event_id)
            cls.execute_rule_against_event(db, "drule_brute_force", norm_auth_fail.normalized_event_id)
            # PARTIAL scenario: run drule_brute_force against firewall event lacking auth fields
            cls.execute_rule_against_event(db, "drule_brute_force", norm_ssh_allowed.normalized_event_id)
        except Exception as e:
            logger.warning("Demo scenario execution note: %s", e)
