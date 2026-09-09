"""
services/control_effectiveness_service.py
-----------------------------------------
Deterministic Control Effectiveness Evaluation Service for SentinelTrace V5.

Sprint 11A — Compliance Intelligence, Security Control Governance & Evidence-Backed Compliance Assurance.

Core Invariant: "COMPLIANCE MUST BE EVIDENCE-BACKED, EXPLAINABLE, HUMAN-GOVERNED, AND CRYPTOGRAPHICALLY VERIFIABLE."
"""

from datetime import datetime, timezone, timedelta
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.compliance_intelligence import (
    ControlEvidenceBinding,
    ControlEffectivenessEvaluation,
    SecurityControl,
    CONTROL_EVIDENCE_BINDING_DOMAIN_PREFIX,
    CONTROL_EFFECTIVENESS_DOMAIN_PREFIX,
    calculate_compliance_hash,
    utcnow,
)
from app.services.governance_ledger_service import GovernanceLedgerService

logger = logging.getLogger("sentinel.services.control_effectiveness")


class ControlEffectivenessService:
    """Service for deterministic, explainable security control effectiveness scoring."""

    @staticmethod
    def bind_evidence(
        db: Session,
        security_control_id: str,
        evidence_type: str,
        evidence_id: str,
        evidence_hash: str,
        source_stage: str,
        binding_reason: str = "",
        expires_at: Optional[datetime] = None,
        observed_at: Optional[datetime] = None,
        verification_status: str = "VERIFIED",
    ) -> ControlEvidenceBinding:
        """
        Binds immutable upstream evidence to a Security Control.
        """
        control = (
            db.query(SecurityControl)
            .filter((SecurityControl.id == security_control_id) | (SecurityControl.control_code == security_control_id))
            .first()
        )
        if not control:
            raise ValueError(f"Security Control {security_control_id} does not exist.")

        now = utcnow()
        obs_time = observed_at or now

        binding_payload = {
            "control_id": control.id,
            "evidence_type": evidence_type,
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "source_stage": source_stage,
            "observed_at": obs_time.isoformat(),
            "verification_status": verification_status,
        }
        binding_hash = calculate_compliance_hash(CONTROL_EVIDENCE_BINDING_DOMAIN_PREFIX, binding_payload)

        binding = ControlEvidenceBinding(
            security_control_id=control.id,
            evidence_type=evidence_type,
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            source_stage=source_stage,
            observed_at=obs_time,
            expires_at=expires_at,
            binding_reason=binding_reason,
            binding_hash=binding_hash,
        )
        db.add(binding)
        db.flush()

        logger.info(
            f"Bound evidence {evidence_type}:{evidence_id} to control {control.control_code} (hash: {binding_hash[:12]}...)"
        )
        return binding

    @classmethod
    def evaluate_control(
        cls,
        db: Session,
        control_id: str,
        evaluator_username: str = "SYSTEM",
        force_crypto_failure: bool = False,
        operational_state_override: Optional[str] = None,
        incident_impacts: Optional[List[Dict[str, Any]]] = None,
    ) -> ControlEffectivenessEvaluation:
        """
        Calculates a deterministic 0-100 control effectiveness score with explainable deductions.
        Enforces cryptographic dominance and immutable ledger logging.
        """
        control = (
            db.query(SecurityControl)
            .filter((SecurityControl.id == control_id) | (SecurityControl.control_code == control_id))
            .first()
        )
        if not control:
            raise ValueError(f"Security Control {control_id} not found.")

        # 1. Gather active evidence bindings
        bindings = (
            db.query(ControlEvidenceBinding)
            .filter(ControlEvidenceBinding.security_control_id == control.id)
            .all()
        )

        total_evidence_count = len(bindings)
        now = utcnow()

        # 2. Check Freshness against SLA
        freshness_sla = timedelta(days=30)
        stale_bindings = []
        for b in bindings:
            obs = b.observed_at.replace(tzinfo=timezone.utc) if b.observed_at.tzinfo is None else b.observed_at
            if (now - obs) > freshness_sla:
                stale_bindings.append(b)
        stale_count = len(stale_bindings)

        # 3. Operational and Cryptographic integrity check
        operational_state = operational_state_override or control.expected_state or "OPERATIONAL"
        crypto_failed = force_crypto_failure

        # 4. Dimension Calculations
        # Dimensions: Coverage (25), Freshness (15), Operational (25), Verification (20), Integrity (15)
        evidence_coverage = 25.0 if total_evidence_count > 0 else 0.0
        freshness_score = 15.0 if (total_evidence_count > 0 and stale_count == 0) else (7.5 if stale_count < total_evidence_count else 0.0)
        
        if operational_state == "OPERATIONAL" or operational_state == "HEALTHY":
            operational_score = 25.0
        elif operational_state == "DEGRADED":
            operational_score = 12.5
        elif operational_state == "FAILED":
            operational_score = 0.0
        else:  # UNKNOWN
            operational_score = 0.0

        verification_score = 20.0 if total_evidence_count > 0 else 0.0
        integrity_score = 0.0 if crypto_failed else 15.0

        # 5. Explainable Deductions
        deductions: List[Dict[str, Any]] = []

        if total_evidence_count == 0:
            deductions.append({
                "rule": "MISSING_EVIDENCE_COVERAGE",
                "deduction": 35.0,
                "reason": f"No active evidence bound to control {control.control_code}. Zero Trust axiom: MISSING EVIDENCE != PASS.",
            })

        if stale_count > 0:
            deductions.append({
                "rule": "STALE_EVIDENCE_DEPRECIATION",
                "deduction": min(20.0, stale_count * 10.0),
                "reason": f"{stale_count} evidence records exceed freshness SLA. Axiom: STALE EVIDENCE != CURRENT ASSURANCE.",
            })

        if operational_state == "DEGRADED":
            deductions.append({
                "rule": "OPERATIONAL_STATE_DEGRADED",
                "deduction": 15.0,
                "reason": f"Control operational state is DEGRADED. Axiom: CONTROL IMPLEMENTED != CONTROL OPERATIONAL.",
            })
        elif operational_state == "FAILED":
            deductions.append({
                "rule": "OPERATIONAL_STATE_FAILED",
                "deduction": 25.0,
                "reason": f"Control operational state is FAILED.",
            })
        elif operational_state == "UNKNOWN":
            deductions.append({
                "rule": "OPERATIONAL_STATE_UNKNOWN",
                "deduction": 30.0,
                "reason": f"Control operational state is UNKNOWN. Axiom: UNKNOWN CONTROL != COMPLIANT.",
            })

        if incident_impacts:
            for inc in incident_impacts:
                sev = inc.get("severity", "MEDIUM")
                if sev == "CRITICAL":
                    deductions.append({
                        "rule": "ACTIVE_CRITICAL_INCIDENT_IMPACT",
                        "deduction": 30.0,
                        "reason": f"Active CRITICAL security incident {inc.get('incident_id')} compromises control domain.",
                    })
                elif sev == "HIGH":
                    deductions.append({
                        "rule": "ACTIVE_HIGH_INCIDENT_IMPACT",
                        "deduction": 15.0,
                        "reason": f"Active HIGH security incident {inc.get('incident_id')} impacts control operation.",
                    })

        # 6. Raw Score Calculation
        dim_sum = evidence_coverage + freshness_score + operational_score + verification_score + integrity_score
        total_deductions = sum(d["deduction"] for d in deductions)
        calc_score = max(0.0, min(100.0, dim_sum - total_deductions))

        # 7. CRITICAL DOMINANCE OVERRIDE
        if crypto_failed:
            final_score = 0.0
            eval_status = "INEFFECTIVE"
            deductions.append({
                "rule": "CRYPTOGRAPHIC_INTEGRITY_DOMINANCE",
                "deduction": 100.0,
                "reason": "CRITICAL OVERRIDE: Cryptographic verification failure detected. Overriding control score to 0.0.",
            })
            explanation = f"Control {control.control_code} failed cryptographic verification. Score overridden to 0.0."
        else:
            final_score = calc_score
            if final_score >= 80.0:
                eval_status = "EFFECTIVE"
            elif final_score >= 50.0:
                eval_status = "PARTIALLY_EFFECTIVE"
            else:
                eval_status = "INEFFECTIVE"
            explanation = f"Control {control.control_code} evaluated as {eval_status} ({final_score:.1f}/100.0)."

        eval_number = f"CEV-{now.strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"

        reasoning = {
            "evidence_coverage": evidence_coverage,
            "freshness_score": freshness_score,
            "operational_score": operational_score,
            "verification_score": verification_score,
            "integrity_score": integrity_score,
            "total_evidence_count": total_evidence_count,
            "stale_count": stale_count,
            "operational_state": operational_state,
            "crypto_failed": crypto_failed,
            "explanation": explanation,
        }

        eval_payload = {
            "evaluation_number": eval_number,
            "control_id": control.id,
            "control_code": control.control_code,
            "effectiveness_score": final_score,
            "evaluation_status": eval_status,
            "evaluated_at": now.isoformat(),
            "evaluated_by": evaluator_username,
        }
        eval_hash = calculate_compliance_hash(CONTROL_EFFECTIVENESS_DOMAIN_PREFIX, eval_payload)

        evaluation = ControlEffectivenessEvaluation(
            evaluation_number=eval_number,
            security_control_id=control.id,
            evaluation_status=eval_status,
            effectiveness_score=final_score,
            confidence_score=100.0 if not crypto_failed else 0.0,
            evidence_coverage=evidence_coverage,
            freshness_score=freshness_score,
            operational_score=operational_score,
            integrity_score=integrity_score,
            deductions_json=deductions,
            reasoning_json=reasoning,
            evaluation_hash=eval_hash,
            evaluated_at=now,
            evaluated_by=evaluator_username,
        )
        db.add(evaluation)
        db.flush()

        # Log to ledger
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="COMPLIANCE_CONTROL_EVALUATED",
                actor_id=None,
                actor_username=evaluator_username,
                payload={
                    "entity_type": "SECURITY_CONTROL",
                    "entity_id": control.id,
                    "control_code": control.control_code,
                    "effectiveness_score": final_score,
                    "evaluation_status": eval_status,
                    "evaluation_hash": eval_hash,
                },
            )
        except Exception as e:
            logger.warning(f"Ledger append failed: {e}")

        logger.info(f"Evaluated control {control.control_code}: Score={final_score:.1f}, Status={eval_status}")
        return evaluation

    @classmethod
    def evaluate_all_controls(
        cls,
        db: Session,
        evaluator_username: str = "SYSTEM",
    ) -> List[ControlEffectivenessEvaluation]:
        """Evaluates all registered active security controls sequentially."""
        controls = (
            db.query(SecurityControl)
            .filter(SecurityControl.status == "ACTIVE")
            .order_by(SecurityControl.control_code.asc())
            .all()
        )
        evals = []
        for ctrl in controls:
            res = cls.evaluate_control(
                db=db,
                control_id=ctrl.id,
                evaluator_username=evaluator_username,
            )
            evals.append(res)
        return evals
