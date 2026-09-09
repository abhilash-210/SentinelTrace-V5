"""
services/detection_rule_trust_service.py
----------------------------------------
Service for evaluating detection rule trustworthiness under semantic drift conditions.

Sprint 6B — Detection Rule Trust Evaluation & Semantic Drift Binding.
Implements deterministic trust score calculation, multi-dependency impact aggregation,
protected field escalation, idempotent evaluation persistence, and complete provenance tracing.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.detection_rule import DetectionRule, DetectionRuleDependency
from app.models.detection_rule_trust import DetectionRuleTrustEvaluation, DetectionTrustAlert
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.ledger import GovernanceLedgerEntry
from app.models.merkle import MerkleProof
from app.models.semantic_interpretation import SemanticDriftAlert, SemanticInterpretation
from app.models.semantic_policy import ProtectedSemanticField
from app.services.detection_trust_alert_service import DetectionTrustAlertService


class DetectionRuleTrustService:
    """Core evaluation engine for detection rule trust and semantic drift binding."""

    EVALUATION_VERSION: int = 1

    @classmethod
    def calculate_trust_score(
        cls,
        equivalence_classification: Optional[str] = "EXACT",
        risk_level: Optional[str] = "NONE",
        is_protected_field: bool = False,
        drift_type: Optional[str] = None,
        has_policy_conflict: bool = False,
        is_unknown: bool = False,
    ) -> Tuple[float, List[str]]:
        """
        Deterministic, explainable trust score calculation.

        Base Trust Score: 1.00
        Deductions:
        - No drift / EXACT: 0.00
        - COMPATIBLE mapping: -0.10
        - AMBIGUOUS mapping: -0.25
        - UNMAPPED value: -0.40
        - INCOMPATIBLE mapping: -0.60
        - PROTECTED SEMANTIC FIELD affected: additional -0.15
        - HIGH semantic risk: additional -0.15
        - CRITICAL semantic risk: additional -0.30
        - POLICY_CONFLICT: forces score to 0.00
        - UNKNOWN dependency: maximum score clamped to <= 0.50

        Clamped: 0.00 <= score <= 1.00
        """
        reasons: List[str] = ["Base trust score: 1.00"]
        score: float = 1.00

        if is_unknown:
            reasons.append("UNKNOWN dependency metadata: Maximum trust score capped at 0.50 (Zero Trust)")
            score = 0.50
            return (score, reasons)

        if has_policy_conflict or drift_type == "POLICY_CONFLICT":
            reasons.append("CRITICAL: POLICY_CONFLICT detected — Detection rule dependency invalidated (-1.00)")
            score = 0.00
            reasons.append(f"Final trust score: {score:.2f}")
            return (score, reasons)

        # 1. Equivalence classification deduction
        eq_upper = (equivalence_classification or "").upper()
        if eq_upper in ("COMPATIBLE", "COMPATIBLE_MAPPING"):
            deduction = 0.10
            score -= deduction
            reasons.append(f"COMPATIBLE semantic mapping detected: -{deduction:.2f}")
        elif eq_upper in ("AMBIGUOUS", "AMBIGUOUS_MAPPING"):
            deduction = 0.25
            score -= deduction
            reasons.append(f"AMBIGUOUS semantic mapping detected: -{deduction:.2f}")
        elif eq_upper in ("UNMAPPED", "UNMAPPED_VALUE", "UNKNOWN_MAPPING"):
            deduction = 0.40
            score -= deduction
            reasons.append(f"UNMAPPED semantic value detected: -{deduction:.2f}")
        elif eq_upper in ("INCOMPATIBLE", "INCOMPATIBLE_MAPPING"):
            deduction = 0.60
            score -= deduction
            reasons.append(f"INCOMPATIBLE semantic mapping detected: -{deduction:.2f}")

        # 2. Protected semantic field penalty
        if is_protected_field and eq_upper not in ("EXACT", ""):
            deduction = 0.15
            score -= deduction
            reasons.append(f"Protected semantic field affected: -{deduction:.2f}")

        # 3. Risk level deduction
        risk_upper = (risk_level or "").upper()
        if risk_upper == "HIGH":
            deduction = 0.15
            score -= deduction
            reasons.append(f"HIGH semantic risk level: -{deduction:.2f}")
        elif risk_upper == "CRITICAL":
            deduction = 0.30
            score -= deduction
            reasons.append(f"CRITICAL semantic risk level: -{deduction:.2f}")

        # 4. Drift type specific penalty if not already covered
        if drift_type and drift_type.upper() in ("SEMANTIC_ANOMALY", "FIELD_DRIFT") and score > 0.70:
            deduction = 0.10
            score -= deduction
            reasons.append(f"Active semantic drift alert '{drift_type}': -{deduction:.2f}")

        # Clamp between 0.00 and 1.00
        score = max(0.00, min(1.00, round(score, 4)))
        reasons.append(f"Final trust score: {score:.2f}")
        return (score, reasons)

    @classmethod
    def determine_trust_status(
        cls,
        trust_score: float,
        is_unknown: bool = False,
        has_policy_conflict: bool = False,
    ) -> Tuple[str, str]:
        """
        Deterministic status classification based on trust score thresholds:
        - 0.90 - 1.00: TRUSTED (Risk: NONE)
        - 0.70 - 0.89: DEGRADED (Risk: LOW)
        - 0.40 - 0.69: AT_RISK (Risk: HIGH)
        - 0.00 - 0.39: INVALID (Risk: CRITICAL)
        - is_unknown: UNKNOWN (Risk: MEDIUM)

        Returns (trust_status, risk_level).
        """
        if is_unknown:
            return ("UNKNOWN", "MEDIUM")
        if has_policy_conflict or trust_score < 0.40:
            return ("INVALID", "CRITICAL")
        if trust_score < 0.70:
            return ("AT_RISK", "HIGH")
        if trust_score <= 0.90:
            return ("DEGRADED", "LOW")
        return ("TRUSTED", "NONE")

    @classmethod
    def generate_explanation(
        cls,
        rule_name: str,
        canonical_field: str,
        trust_status: str,
        trust_score: float,
        reasons: List[str],
        is_protected_field: bool = False,
        vendor_name: str = "Generic",
    ) -> str:
        """Generate human-readable cybersecurity explanation for trust evaluation."""
        if trust_status == "TRUSTED":
            return (
                f"Detection rule '{rule_name}' for vendor '{vendor_name}' is fully TRUSTED "
                f"(score: {trust_score:.2f}). All required canonical field dependencies are aligned "
                f"with exact semantic policies and exhibit zero drift."
            )

        if trust_status == "DEGRADED":
            protected_note = " (Field is a protected semantic asset)" if is_protected_field else ""
            return (
                f"Detection rule '{rule_name}' trust is DEGRADED (score: {trust_score:.2f}) "
                f"due to low-risk or compatible semantic variance on canonical field '{canonical_field}'"
                f"{protected_note}. Rule logic remains executable but security analysts should monitor."
            )

        if trust_status == "AT_RISK":
            protected_note = " Because this is a protected semantic field, risk is elevated." if is_protected_field else ""
            return (
                f"Detection rule '{rule_name}' is AT RISK (score: {trust_score:.2f}) "
                f"because canonical field '{canonical_field}' exhibits ambiguous semantic drift "
                f"under vendor '{vendor_name}'.{protected_note} Potential for false negatives or bypass."
            )

        if trust_status == "INVALID":
            return (
                f"Detection rule '{rule_name}' is INVALIDATED (score: {trust_score:.2f}). "
                f"Canonical field '{canonical_field}' encountered incompatible semantic mapping, "
                f"unmapped critical security values, or policy conflict. Detection queries cannot be trusted."
            )

        return (
            f"Detection rule '{rule_name}' trust status is UNKNOWN (score: {trust_score:.2f}). "
            f"Dependency '{canonical_field}' could not be resolved against active semantic policies. "
            f"Zero Trust applies: UNKNOWN is never treated as safe."
        )

    @classmethod
    def evaluate_rule_trust(
        cls,
        db: Session,
        rule_id: str,
        canonical_field: Optional[str] = None,
        normalized_event_id: Optional[str] = None,
        interpretation_id: Optional[str] = None,
        drift_alert_id: Optional[str] = None,
    ) -> DetectionRuleTrustEvaluation:
        """
        Evaluate trust for a detection rule across its dependencies.

        - Enforces idempotency: Returns existing record if exact same context was already evaluated.
        - Applies worst-dependency impact principle for multi-dependency rules.
        - Checks protected semantic field status.
        - Automatically creates DetectionTrustAlert if trust is degraded/at risk/invalid.
        """
        rule = db.query(DetectionRule).filter(DetectionRule.rule_id == rule_id).first()
        if not rule:
            raise ValueError(f"Detection rule '{rule_id}' not found.")

        # Idempotency check: Look for existing evaluation with exact same tuple
        existing = (
            db.query(DetectionRuleTrustEvaluation)
            .filter(
                DetectionRuleTrustEvaluation.rule_id == rule_id,
                DetectionRuleTrustEvaluation.normalized_event_id == normalized_event_id,
                DetectionRuleTrustEvaluation.interpretation_id == interpretation_id,
                DetectionRuleTrustEvaluation.drift_alert_id == drift_alert_id,
                DetectionRuleTrustEvaluation.evaluation_version == cls.EVALUATION_VERSION,
            )
            .first()
        )
        if existing:
            return existing

        # Fetch protected canonical fields
        protected_fields = {
            p.field_name
            for p in db.query(ProtectedSemanticField)
            .filter(ProtectedSemanticField.is_protected.is_(True))
            .all()
        }

        # Fetch dependencies for this rule
        dependencies = (
            db.query(DetectionRuleDependency)
            .filter(DetectionRuleDependency.rule_id == rule_id)
            .all()
        )

        if not dependencies:
            # Rule has no declared dependencies -> UNKNOWN
            score, reasons = cls.calculate_trust_score(is_unknown=True)
            status, risk = cls.determine_trust_status(score, is_unknown=True)
            explanation = cls.generate_explanation(
                rule_name=rule.rule_name,
                canonical_field="NONE_DECLARED",
                trust_status=status,
                trust_score=score,
                reasons=reasons,
                vendor_name=rule.vendor_name,
            )
            eval_record = DetectionRuleTrustEvaluation(
                rule_id=rule_id,
                normalized_event_id=normalized_event_id,
                interpretation_id=interpretation_id,
                drift_alert_id=drift_alert_id,
                canonical_field="NONE_DECLARED",
                trust_status=status,
                trust_score=score,
                risk_level=risk,
                evaluation_reasons=reasons,
                explanation=explanation,
                evaluation_version=cls.EVALUATION_VERSION,
                created_at=datetime.now(timezone.utc),
            )
            db.add(eval_record)
            db.commit()
            db.refresh(eval_record)
            DetectionTrustAlertService.generate_alert_if_needed(db, eval_record, is_protected_field=False)
            return eval_record

        # Fetch semantic interpretation if provided
        interpretation = None
        if interpretation_id:
            interpretation = (
                db.query(SemanticInterpretation)
                .filter(SemanticInterpretation.interpretation_id == interpretation_id)
                .first()
            )

        # Fetch drift alert if provided
        drift_alert = None
        if drift_alert_id:
            drift_alert = (
                db.query(SemanticDriftAlert)
                .filter(SemanticDriftAlert.alert_id == drift_alert_id)
                .first()
            )

        # Evaluate each dependency
        evaluated_deps: List[Dict[str, Any]] = []
        worst_score: float = 1.00
        worst_status: str = "TRUSTED"
        worst_risk: str = "NONE"
        worst_field: str = dependencies[0].canonical_field
        worst_is_protected: bool = False
        all_reasons: List[str] = []

        for dep in dependencies:
            field_name = dep.canonical_field
            is_prot = field_name in protected_fields

            # Check if this specific field has active drift or interpretation
            field_eq = "EXACT"
            field_risk = "NONE"
            field_drift_type = None

            drift_field = (
                getattr(drift_alert, "affected_field", None)
                or (drift_alert.interpretation.canonical_field if drift_alert.interpretation else None)
                or getattr(drift_alert, "expected_value", None)
            ) if drift_alert else None

            if drift_alert and (
                drift_field == field_name
                or (drift_field and drift_field == field_name.split(".")[-1])
            ):
                field_drift_type = drift_alert.drift_type
                field_risk = drift_alert.severity
                if drift_alert.drift_type == "AMBIGUOUS_MAPPING":
                    field_eq = "AMBIGUOUS"
                elif drift_alert.drift_type in ("INCOMPATIBLE_MAPPING", "TYPE_INCOMPATIBLE"):
                    field_eq = "INCOMPATIBLE"
                elif drift_alert.drift_type == "UNMAPPED_VALUE":
                    field_eq = "UNMAPPED"
                elif drift_alert.drift_type == "COMPATIBLE_MAPPING":
                    field_eq = "COMPATIBLE"
            elif interpretation and interpretation.canonical_field == field_name:
                field_eq = interpretation.equivalence_classification or "EXACT"
                field_risk = interpretation.risk_level or "NONE"

            # Compute score for this dependency
            dep_score, dep_reasons = cls.calculate_trust_score(
                equivalence_classification=field_eq,
                risk_level=field_risk,
                is_protected_field=is_prot,
                drift_type=field_drift_type,
            )
            dep_status, dep_risk = cls.determine_trust_status(dep_score)

            all_reasons.append(f"Dependency [{field_name}]: {dep_status} (Score: {dep_score:.2f})")
            for r in dep_reasons:
                all_reasons.append(f"  • {r}")

            evaluated_deps.append({
                "field": field_name,
                "score": dep_score,
                "status": dep_status,
                "risk": dep_risk,
                "is_protected": is_prot,
            })

            # Check if this is the worst dependency
            if dep_score < worst_score:
                worst_score = dep_score
                worst_status = dep_status
                worst_risk = dep_risk
                worst_field = field_name
                worst_is_protected = is_prot

        # Synthesis
        all_reasons.append(
            f"Overall Rule Trust (Worst dependency '{worst_field}' dominates): "
            f"{worst_status} (Score: {worst_score:.2f})"
        )

        explanation = cls.generate_explanation(
            rule_name=rule.rule_name,
            canonical_field=worst_field,
            trust_status=worst_status,
            trust_score=worst_score,
            reasons=all_reasons,
            is_protected_field=worst_is_protected,
            vendor_name=rule.vendor_name,
        )

        eval_record = DetectionRuleTrustEvaluation(
            rule_id=rule_id,
            normalized_event_id=normalized_event_id,
            interpretation_id=interpretation_id,
            drift_alert_id=drift_alert_id,
            canonical_field=worst_field if len(dependencies) == 1 else f"{worst_field} (1/{len(dependencies)} deps)",
            trust_status=worst_status,
            trust_score=worst_score,
            risk_level=worst_risk,
            evaluation_reasons=all_reasons,
            explanation=explanation,
            evaluation_version=cls.EVALUATION_VERSION,
            created_at=datetime.now(timezone.utc),
        )
        db.add(eval_record)
        db.commit()
        db.refresh(eval_record)

        # Generate alert if trust is degraded or at risk
        DetectionTrustAlertService.generate_alert_if_needed(
            db, eval_record, is_protected_field=worst_is_protected
        )

        return eval_record

    @classmethod
    def evaluate_rules_for_drift_alert(
        cls,
        db: Session,
        alert_id: str,
    ) -> List[DetectionRuleTrustEvaluation]:
        """
        Find all detection rules dependent on the canonical field of a semantic drift alert,
        evaluate each rule, and return the generated evaluation records.
        """
        drift_alert = (
            db.query(SemanticDriftAlert)
            .filter(SemanticDriftAlert.alert_id == alert_id)
            .first()
        )
        if not drift_alert:
            raise ValueError(f"Semantic drift alert '{alert_id}' not found.")

        affected_field = (
            getattr(drift_alert, "affected_field", None)
            or (drift_alert.interpretation.canonical_field if drift_alert.interpretation else None)
            or getattr(drift_alert, "expected_value", None)
            or "action"
        )

        # Query rules dependent on this canonical field (exact match or suffix match)
        deps = (
            db.query(DetectionRuleDependency)
            .filter(
                (DetectionRuleDependency.canonical_field == affected_field)
                | (DetectionRuleDependency.canonical_field.like(f"%.{affected_field}"))
                | (DetectionRuleDependency.canonical_field == affected_field.split(".")[-1])
            )
            .all()
        )

        evaluated_records: List[DetectionRuleTrustEvaluation] = []
        seen_rule_ids = set()

        for dep in deps:
            if dep.rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(dep.rule_id)

            eval_record = cls.evaluate_rule_trust(
                db=db,
                rule_id=dep.rule_id,
                canonical_field=dep.canonical_field,
                normalized_event_id=drift_alert.normalized_event_id,
                interpretation_id=drift_alert.interpretation_id,
                drift_alert_id=drift_alert.alert_id,
            )
            evaluated_records.append(eval_record)

        return evaluated_records

    @staticmethod
    def list_evaluations(
        db: Session,
        rule_id: Optional[str] = None,
        trust_status: Optional[str] = None,
        canonical_field: Optional[str] = None,
        risk_level: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[DetectionRuleTrustEvaluation]:
        """Query trust evaluations with optional filtering and pagination."""
        query = db.query(DetectionRuleTrustEvaluation)
        if rule_id:
            query = query.filter(DetectionRuleTrustEvaluation.rule_id == rule_id)
        if trust_status:
            query = query.filter(DetectionRuleTrustEvaluation.trust_status == trust_status.upper())
        if canonical_field:
            query = query.filter(DetectionRuleTrustEvaluation.canonical_field.ilike(f"%{canonical_field}%"))
        if risk_level:
            query = query.filter(DetectionRuleTrustEvaluation.risk_level == risk_level.upper())
        return query.order_by(DetectionRuleTrustEvaluation.created_at.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_evaluation_by_id(
        db: Session,
        evaluation_id: str,
    ) -> Optional[DetectionRuleTrustEvaluation]:
        """Fetch a single evaluation record by its evaluation_id."""
        return (
            db.query(DetectionRuleTrustEvaluation)
            .filter(DetectionRuleTrustEvaluation.evaluation_id == evaluation_id)
            .first()
        )

    @staticmethod
    def get_rule_trust_history(
        db: Session,
        rule_id: str,
        limit: int = 50,
    ) -> List[DetectionRuleTrustEvaluation]:
        """Retrieve immutable chronological trust evaluation history for a given rule."""
        return (
            db.query(DetectionRuleTrustEvaluation)
            .filter(DetectionRuleTrustEvaluation.rule_id == rule_id)
            .order_by(DetectionRuleTrustEvaluation.created_at.desc())
            .limit(limit)
            .all()
        )

    @classmethod
    def get_trust_trace(
        cls,
        db: Session,
        evaluation_id: str,
    ) -> Dict[str, Any]:
        """
        Construct the complete end-to-end provenance trace from Raw Evidence to Detection Trust Alert:

        1. Raw Evidence (IngestedEvent)
        2. Normalized Event (NormalizedEvent)
        3. Semantic Interpretation (SemanticInterpretation)
        4. Semantic Drift Alert (SemanticDriftAlert)
        5. Affected Canonical Field & Protected Field Status
        6. Detection Rule Dependency (DetectionRuleDependency)
        7. Detection Rule (DetectionRule)
        8. Detection Rule Trust Evaluation (DetectionRuleTrustEvaluation)
        9. Detection Trust Alert (DetectionTrustAlert)
        10. Cryptographic Governance Ledger / Merkle Proof (if available)
        """
        eval_record = (
            db.query(DetectionRuleTrustEvaluation)
            .filter(DetectionRuleTrustEvaluation.evaluation_id == evaluation_id)
            .first()
        )
        if not eval_record:
            raise ValueError(f"Trust evaluation '{evaluation_id}' not found.")

        rule = db.query(DetectionRule).filter(DetectionRule.rule_id == eval_record.rule_id).first()
        chain: List[Dict[str, Any]] = []
        step_num = 1

        # 1. Raw Evidence
        ingested_event = None
        if eval_record.normalized_event_id:
            norm = (
                db.query(NormalizedEvent)
                .filter(NormalizedEvent.normalized_event_id == eval_record.normalized_event_id)
                .first()
            )
            if norm:
                ingested_event = (
                    db.query(IngestedEvent)
                    .filter(IngestedEvent.event_id == norm.original_event_id)
                    .first()
                )

        if ingested_event:
            chain.append({
                "step_number": step_num,
                "stage_name": "RAW_EVIDENCE_VAULT",
                "entity_id": ingested_event.event_id,
                "entity_type": "IngestedEvent",
                "summary": f"Immutable raw evidence preserved with SHA-256: {ingested_event.raw_content_hash[:16]}...",
                "details": {
                    "event_id": ingested_event.event_id,
                    "source_name": ingested_event.source_name,
                    "source_type": ingested_event.source_type,
                    "raw_content_hash": ingested_event.raw_content_hash,
                    "processing_status": ingested_event.processing_status,
                },
                "timestamp": ingested_event.ingested_at.isoformat() if ingested_event.ingested_at else None,
            })
            step_num += 1

        # 2. Normalized Event
        if eval_record.normalized_event_id:
            norm = (
                db.query(NormalizedEvent)
                .filter(NormalizedEvent.normalized_event_id == eval_record.normalized_event_id)
                .first()
            )
            if norm:
                chain.append({
                    "step_number": step_num,
                    "stage_name": "OCSF_NORMALIZATION",
                    "entity_id": norm.normalized_event_id,
                    "entity_type": "NormalizedEvent",
                    "summary": f"Canonical OCSF Class {norm.class_uid} event parsed from profile {norm.source_profile_id}",
                    "details": {
                        "normalized_event_id": norm.normalized_event_id,
                        "class_uid": norm.class_uid,
                        "category_uid": norm.category_uid,
                        "activity_id": norm.activity_id,
                        "source_profile_id": norm.source_profile_id,
                    },
                    "timestamp": norm.created_at.isoformat() if norm.created_at else None,
                })
                step_num += 1

        # 3. Semantic Interpretation
        if eval_record.interpretation_id:
            interp = (
                db.query(SemanticInterpretation)
                .filter(SemanticInterpretation.interpretation_id == eval_record.interpretation_id)
                .first()
            )
            if interp:
                chain.append({
                    "step_number": step_num,
                    "stage_name": "SEMANTIC_INTERPRETATION",
                    "entity_id": interp.interpretation_id,
                    "entity_type": "SemanticInterpretation",
                    "summary": f"Interpreted '{interp.source_field}={interp.source_value}' -> '{interp.canonical_field}={interp.interpreted_value}' ({interp.equivalence_classification})",
                    "details": {
                        "interpretation_id": interp.interpretation_id,
                        "policy_id": interp.policy_id,
                        "vendor_name": interp.vendor_name,
                        "source_field": interp.source_field,
                        "source_value": interp.source_value,
                        "canonical_field": interp.canonical_field,
                        "interpreted_value": interp.interpreted_value,
                        "equivalence_classification": interp.equivalence_classification,
                        "confidence_score": interp.confidence_score,
                    },
                    "timestamp": interp.created_at.isoformat() if interp.created_at else None,
                })
                step_num += 1

        # 4. Semantic Drift Alert
        if eval_record.drift_alert_id:
            drift = (
                db.query(SemanticDriftAlert)
                .filter(SemanticDriftAlert.alert_id == eval_record.drift_alert_id)
                .first()
            )
            if drift:
                drift_field = (
                    getattr(drift, "affected_field", None)
                    or (drift.interpretation.canonical_field if drift.interpretation else None)
                    or getattr(drift, "expected_value", None)
                    or "action"
                )
                chain.append({
                    "step_number": step_num,
                    "stage_name": "SEMANTIC_DRIFT_ALERT",
                    "entity_id": drift.alert_id,
                    "entity_type": "SemanticDriftAlert",
                    "summary": f"Drift Alert [{drift.drift_type}] on field '{drift_field}' (Severity: {drift.severity})",
                    "details": {
                        "alert_id": drift.alert_id,
                        "drift_type": drift.drift_type,
                        "severity": drift.severity,
                        "affected_field": drift_field,
                        "description": drift.description,
                        "status": drift.status,
                    },
                    "timestamp": drift.detected_at.isoformat() if drift.detected_at else None,
                })
                step_num += 1

        # 5. Detection Rule Dependency
        deps = (
            db.query(DetectionRuleDependency)
            .filter(DetectionRuleDependency.rule_id == eval_record.rule_id)
            .all()
        )
        chain.append({
            "step_number": step_num,
            "stage_name": "DEPENDENCY_MAPPING",
            "entity_id": f"deps_{eval_record.rule_id}",
            "entity_type": "DetectionRuleDependencySet",
            "summary": f"Rule depends on {len(deps)} canonical field(s): {', '.join([d.canonical_field for d in deps])}",
            "details": {
                "dependencies": [d.to_dict() for d in deps],
                "evaluated_canonical_field": eval_record.canonical_field,
            },
            "timestamp": eval_record.created_at.isoformat() if eval_record.created_at else None,
        })
        step_num += 1

        # 6. Detection Rule
        if rule:
            chain.append({
                "step_number": step_num,
                "stage_name": "DETECTION_RULE",
                "entity_id": rule.rule_id,
                "entity_type": "DetectionRule",
                "summary": f"Target rule '{rule.rule_name}' (Vendor: {rule.vendor_name}, Severity: {rule.severity})",
                "details": rule.to_dict(),
                "timestamp": rule.created_at.isoformat() if rule.created_at else None,
            })
            step_num += 1

        # 7. Trust Evaluation
        chain.append({
            "step_number": step_num,
            "stage_name": "TRUST_EVALUATION",
            "entity_id": eval_record.evaluation_id,
            "entity_type": "DetectionRuleTrustEvaluation",
            "summary": f"Trust Status: {eval_record.trust_status} (Score: {eval_record.trust_score:.2f})",
            "details": eval_record.to_dict(),
            "timestamp": eval_record.created_at.isoformat() if eval_record.created_at else None,
        })
        step_num += 1

        # 8. Detection Trust Alert (if any)
        alerts = (
            db.query(DetectionTrustAlert)
            .filter(DetectionTrustAlert.evaluation_id == eval_record.evaluation_id)
            .all()
        )
        for a in alerts:
            chain.append({
                "step_number": step_num,
                "stage_name": "DETECTION_TRUST_ALERT",
                "entity_id": a.alert_id,
                "entity_type": "DetectionTrustAlert",
                "summary": f"Alert [{a.alert_type}] - Severity {a.severity} (Status: {a.status})",
                "details": a.to_dict(),
                "timestamp": a.created_at.isoformat() if a.created_at else None,
            })
            step_num += 1

        return {
            "evaluation_id": eval_record.evaluation_id,
            "rule_id": eval_record.rule_id,
            "rule_name": rule.rule_name if rule else "Unknown",
            "trust_status": eval_record.trust_status,
            "trust_score": eval_record.trust_score,
            "provenance_chain": chain,
        }

    @staticmethod
    def get_trust_kpis(db: Session) -> Dict[str, int]:
        """Aggregate KPI statistics for the trust intelligence dashboard."""
        total_evals = db.query(DetectionRuleTrustEvaluation).count()
        trusted = (
            db.query(DetectionRuleTrustEvaluation)
            .filter(DetectionRuleTrustEvaluation.trust_status == "TRUSTED")
            .count()
        )
        degraded = (
            db.query(DetectionRuleTrustEvaluation)
            .filter(DetectionRuleTrustEvaluation.trust_status == "DEGRADED")
            .count()
        )
        at_risk = (
            db.query(DetectionRuleTrustEvaluation)
            .filter(DetectionRuleTrustEvaluation.trust_status == "AT_RISK")
            .count()
        )
        invalid = (
            db.query(DetectionRuleTrustEvaluation)
            .filter(DetectionRuleTrustEvaluation.trust_status == "INVALID")
            .count()
        )
        unknown = (
            db.query(DetectionRuleTrustEvaluation)
            .filter(DetectionRuleTrustEvaluation.trust_status == "UNKNOWN")
            .count()
        )
        open_alerts = (
            db.query(DetectionTrustAlert)
            .filter(DetectionTrustAlert.status == "OPEN")
            .count()
        )
        critical_alerts = (
            db.query(DetectionTrustAlert)
            .filter(
                DetectionTrustAlert.status == "OPEN",
                DetectionTrustAlert.severity == "CRITICAL",
            )
            .count()
        )

        return {
            "total_evaluations": total_evals,
            "trusted_rules_count": trusted,
            "degraded_rules_count": degraded,
            "at_risk_rules_count": at_risk,
            "invalid_rules_count": invalid,
            "unknown_rules_count": unknown,
            "open_alerts_count": open_alerts,
            "critical_alerts_count": critical_alerts,
        }

    @classmethod
    def seed_demo_trust_scenarios(cls, db: Session) -> None:
        """
        Seed deterministic demonstration scenarios for Sprint 6B.

        Scenario 1: Cisco ASA - PERMIT -> ALLOWED (COMPATIBLE -> DEGRADED/TRUSTED, score 0.90)
        Scenario 2: Demo Vendor - PERMIT -> MONITORED (AMBIGUOUS on protected 'action.result' -> AT_RISK, score 0.60)
        Scenario 3: Unregistered Vendor - UNMAPPED -> 'authentication.outcome' (INVALID, score 0.30 -> CRITICAL Alert)
        Scenario 4: Unaffected Detection Rule - depends only on 'src_endpoint_ip', 'dst_endpoint_ip' (TRUSTED, score 1.00 -> Proves Dependency Isolation)
        """
        # Ensure rules and protected fields exist
        rules = {r.rule_id: r for r in db.query(DetectionRule).all()}
        if not rules:
            return

        # Scenario 1: Cisco ASA Access Rule (drule_fw_deny_scan or drule_cisco_asa_permit)
        fw_rule = rules.get("drule_fw_deny_scan")
        if fw_rule:
            score, reasons = cls.calculate_trust_score(
                equivalence_classification="COMPATIBLE",
                risk_level="LOW",
                is_protected_field=False,
            )
            status, risk = cls.determine_trust_status(score)
            explanation = cls.generate_explanation(
                rule_name=fw_rule.rule_name,
                canonical_field="disposition",
                trust_status=status,
                trust_score=score,
                reasons=reasons,
                vendor_name=fw_rule.vendor_name,
            )
            existing = (
                db.query(DetectionRuleTrustEvaluation)
                .filter(DetectionRuleTrustEvaluation.rule_id == fw_rule.rule_id)
                .first()
            )
            if not existing:
                eval1 = DetectionRuleTrustEvaluation(
                    rule_id=fw_rule.rule_id,
                    canonical_field="disposition",
                    trust_status=status,
                    trust_score=score,
                    risk_level=risk,
                    evaluation_reasons=reasons,
                    explanation=explanation,
                    evaluation_version=cls.EVALUATION_VERSION,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(eval1)
                db.commit()

        # Scenario 2: Ambiguous mapping on protected field action.result -> drule_demo_vendor_auth / drule_win_sec_logon
        win_rule = rules.get("drule_win_sec_logon")
        if win_rule:
            score2, reasons2 = cls.calculate_trust_score(
                equivalence_classification="AMBIGUOUS",
                risk_level="MEDIUM",
                is_protected_field=True,
            )
            status2, risk2 = cls.determine_trust_status(score2)
            explanation2 = cls.generate_explanation(
                rule_name=win_rule.rule_name,
                canonical_field="action.result",
                trust_status=status2,
                trust_score=score2,
                reasons=reasons2,
                is_protected_field=True,
                vendor_name=win_rule.vendor_name,
            )
            existing2 = (
                db.query(DetectionRuleTrustEvaluation)
                .filter(DetectionRuleTrustEvaluation.rule_id == win_rule.rule_id)
                .first()
            )
            if not existing2:
                eval2 = DetectionRuleTrustEvaluation(
                    rule_id=win_rule.rule_id,
                    canonical_field="action.result",
                    trust_status=status2,
                    trust_score=score2,
                    risk_level=risk2,
                    evaluation_reasons=reasons2,
                    explanation=explanation2,
                    evaluation_version=cls.EVALUATION_VERSION,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(eval2)
                db.commit()
                DetectionTrustAlertService.generate_alert_if_needed(db, eval2, is_protected_field=True)

        # Scenario 3: Unregistered vendor unmapped value on authentication.outcome -> drule_linux_ssh_brute
        ssh_rule = rules.get("drule_linux_ssh_brute")
        if ssh_rule:
            score3, reasons3 = cls.calculate_trust_score(
                equivalence_classification="UNMAPPED",
                risk_level="CRITICAL",
                is_protected_field=True,
            )
            status3, risk3 = cls.determine_trust_status(score3)
            explanation3 = cls.generate_explanation(
                rule_name=ssh_rule.rule_name,
                canonical_field="authentication.outcome",
                trust_status=status3,
                trust_score=score3,
                reasons=reasons3,
                is_protected_field=True,
                vendor_name=ssh_rule.vendor_name,
            )
            existing3 = (
                db.query(DetectionRuleTrustEvaluation)
                .filter(DetectionRuleTrustEvaluation.rule_id == ssh_rule.rule_id)
                .first()
            )
            if not existing3:
                eval3 = DetectionRuleTrustEvaluation(
                    rule_id=ssh_rule.rule_id,
                    canonical_field="authentication.outcome",
                    trust_status=status3,
                    trust_score=score3,
                    risk_level=risk3,
                    evaluation_reasons=reasons3,
                    explanation=explanation3,
                    evaluation_version=cls.EVALUATION_VERSION,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(eval3)
                db.commit()
                DetectionTrustAlertService.generate_alert_if_needed(db, eval3, is_protected_field=True)

        # Scenario 4: Unaffected Detection Rule (drule_suri_dns_tunnel) -> depends on dns_query, src_endpoint_ip
        dns_rule = rules.get("drule_suri_dns_tunnel")
        if dns_rule:
            score4, reasons4 = cls.calculate_trust_score(
                equivalence_classification="EXACT",
                risk_level="NONE",
                is_protected_field=False,
            )
            status4, risk4 = cls.determine_trust_status(score4)
            explanation4 = cls.generate_explanation(
                rule_name=dns_rule.rule_name,
                canonical_field="dns_query",
                trust_status=status4,
                trust_score=score4,
                reasons=reasons4,
                vendor_name=dns_rule.vendor_name,
            )
            existing4 = (
                db.query(DetectionRuleTrustEvaluation)
                .filter(DetectionRuleTrustEvaluation.rule_id == dns_rule.rule_id)
                .first()
            )
            if not existing4:
                eval4 = DetectionRuleTrustEvaluation(
                    rule_id=dns_rule.rule_id,
                    canonical_field="dns_query",
                    trust_status=status4,
                    trust_score=score4,
                    risk_level=risk4,
                    evaluation_reasons=reasons4,
                    explanation=explanation4,
                    evaluation_version=cls.EVALUATION_VERSION,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(eval4)
                db.commit()
