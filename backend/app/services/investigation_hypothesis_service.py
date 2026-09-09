"""
services/investigation_hypothesis_service.py
--------------------------------------------
Deterministic Hypothesis Formulation & Evidence-Driven Confidence Engine.

Sprint 12A — Unified SOC Investigation & Security Case Management.
Core Invariant: "INCONCLUSIVE MUST NEVER AUTOMATICALLY BECOME SUPPORTED. NO ML / NO LLM."
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.security_investigation import (
    SecurityInvestigationCase,
    InvestigationHypothesis,
    InvestigationArtifactBinding,
)


class InvestigationHypothesisService:
    """
    Formulates and evaluates investigative hypotheses using deterministic, explainable logic.
    """

    @staticmethod
    def create_hypothesis(
        db: Session,
        case_id: str,
        hypothesis_title: str,
        hypothesis_statement: str,
        confidence_score: float = 0.5,
        status: str = "PROPOSED",
        deductions_json: Optional[List[Dict[str, Any]]] = None,
        supporting_evidence_ids: Optional[List[str]] = None,
        analyst_notes: Optional[str] = None,
        actor_user_id: str = "SYSTEM",
    ) -> InvestigationHypothesis:
        case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found.")

        clamped_conf = max(0.0, min(1.0, float(confidence_score)))
        valid_status = status.upper().strip()
        if valid_status not in ("PROPOSED", "UNDER_INVESTIGATION", "SUPPORTED", "REFUTED", "INCONCLUSIVE"):
            valid_status = "PROPOSED"

        hypothesis = InvestigationHypothesis(
            case_id=case_id,
            hypothesis_title=hypothesis_title.strip(),
            hypothesis_statement=hypothesis_statement.strip(),
            confidence_score=clamped_conf,
            status=valid_status,
            deductions_json=deductions_json or [],
            supporting_evidence_ids=supporting_evidence_ids or [],
            analyst_notes=analyst_notes,
            created_by=actor_user_id,
        )
        db.add(hypothesis)
        db.flush()
        return hypothesis

    @staticmethod
    def evaluate_hypothesis_confidence(
        base_confidence: float = 0.80,
        has_direct_evidence: bool = True,
        evidence_count: int = 1,
        has_contradictory_evidence: bool = False,
        is_unverified_source: bool = False,
        missing_privilege_escalation: bool = False,
        incomplete_telemetry: bool = False,
    ) -> Dict[str, Any]:
        """
        Calculates explainable confidence score with itemized deductions.
        Zero-Trust: Incomplete telemetry or missing steps deduct confidence.
        """
        base = max(0.0, min(1.0, float(base_confidence)))
        deductions: List[Dict[str, Any]] = []

        if not has_direct_evidence or evidence_count == 0:
            deductions.append({
                "reason": "NO_DIRECT_EVIDENCE",
                "points": 0.35,
                "details": "Hypothesis has no directly bound verifiable evidence.",
            })

        if has_contradictory_evidence:
            deductions.append({
                "reason": "CONTRADICTORY_EVIDENCE_OBSERVED",
                "points": 0.40,
                "details": "Telemetry contains signals directly refuting the hypothesis.",
            })

        if is_unverified_source:
            deductions.append({
                "reason": "UNVERIFIED_SOURCE_DATA",
                "points": 0.15,
                "details": "Supporting signals originated from unverified external feed.",
            })

        if missing_privilege_escalation:
            deductions.append({
                "reason": "NO_PRIVILEGE_ESCALATION_OBSERVED",
                "points": 0.10,
                "details": "Attack hypothesis assumes elevated privilege but none was captured in logs.",
            })

        if incomplete_telemetry:
            deductions.append({
                "reason": "INCOMPLETE_TELEMETRY_COVERAGE",
                "points": 0.15,
                "details": "Observable gaps exist in host/network audit telemetry.",
            })

        total_deduction = sum(d["points"] for d in deductions)
        final_conf = max(0.0, min(1.0, round(base - total_deduction, 2)))

        # Determine suggested status
        if has_contradictory_evidence or final_conf < 0.20:
            suggested_status = "REFUTED"
        elif final_conf >= 0.70 and evidence_count >= 2:
            suggested_status = "SUPPORTED"
        elif incomplete_telemetry or not has_direct_evidence or final_conf <= 0.45:
            suggested_status = "INCONCLUSIVE"
        else:
            suggested_status = "UNDER_INVESTIGATION"

        return {
            "base_confidence": base,
            "deductions": deductions,
            "final_confidence": final_conf,
            "suggested_status": suggested_status,
        }

    @staticmethod
    def generate_rule_based_hypotheses(
        db: Session,
        case_id: str,
        actor_user_id: str = "SYSTEM",
    ) -> List[InvestigationHypothesis]:
        """
        Generates deterministic hypotheses based on the types of bound artifacts.
        """
        case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found.")

        bindings = db.query(InvestigationArtifactBinding).filter(InvestigationArtifactBinding.case_id == case_id).all()
        artifact_types = {b.artifact_type for b in bindings}
        created_hypotheses: List[InvestigationHypothesis] = []

        # Rule 1: Threat Indicator + Security Incident -> Active Adversary Infrastructure
        if "THREAT_INDICATOR" in artifact_types and "SECURITY_INCIDENT" in artifact_types:
            eval_res = InvestigationHypothesisService.evaluate_hypothesis_confidence(
                base_confidence=0.85,
                has_direct_evidence=True,
                evidence_count=len(bindings),
                incomplete_telemetry=False,
            )
            h = InvestigationHypothesisService.create_hypothesis(
                db=db,
                case_id=case_id,
                hypothesis_title="Adversary Infrastructure Exploitation",
                hypothesis_statement="Correlated malicious indicators suggest active external adversary command-and-control communication.",
                confidence_score=eval_res["final_confidence"],
                status=eval_res["suggested_status"],
                deductions_json=eval_res["deductions"],
                supporting_evidence_ids=[b.artifact_id for b in bindings if b.artifact_type in ("THREAT_INDICATOR", "SECURITY_INCIDENT")],
                actor_user_id=actor_user_id,
            )
            created_hypotheses.append(h)

        # Rule 2: Detection Result without Incident -> Benign Administrative Activity vs Unconfirmed Probe
        if "DETECTION_RESULT" in artifact_types:
            eval_res = InvestigationHypothesisService.evaluate_hypothesis_confidence(
                base_confidence=0.60,
                has_direct_evidence=True,
                evidence_count=1,
                incomplete_telemetry=True,
            )
            h = InvestigationHypothesisService.create_hypothesis(
                db=db,
                case_id=case_id,
                hypothesis_title="Benign Administrative Anomaly",
                hypothesis_statement="Observed detection signals may correspond to authorized maintenance or diagnostic procedures.",
                confidence_score=eval_res["final_confidence"],
                status="UNDER_INVESTIGATION",
                deductions_json=eval_res["deductions"],
                supporting_evidence_ids=[b.artifact_id for b in bindings if b.artifact_type == "DETECTION_RESULT"],
                actor_user_id=actor_user_id,
            )
            created_hypotheses.append(h)

        # Default fallback hypothesis if none generated
        if not created_hypotheses:
            eval_res = InvestigationHypothesisService.evaluate_hypothesis_confidence(
                base_confidence=0.50,
                has_direct_evidence=len(bindings) > 0,
                evidence_count=len(bindings),
                incomplete_telemetry=True,
            )
            h = InvestigationHypothesisService.create_hypothesis(
                db=db,
                case_id=case_id,
                hypothesis_title="General Security Inconsistency",
                hypothesis_statement="Investigation opened to verify whether anomalous telemetry constitutes unauthorized access or benign drift.",
                confidence_score=eval_res["final_confidence"],
                status="INCONCLUSIVE",
                deductions_json=eval_res["deductions"],
                supporting_evidence_ids=[b.artifact_id for b in bindings],
                actor_user_id=actor_user_id,
            )
            created_hypotheses.append(h)

        return created_hypotheses
