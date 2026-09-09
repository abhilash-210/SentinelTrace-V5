"""
services/investigation_impact_service.py
----------------------------------------
Multi-Dimensional CIA, Business, and Compliance Impact Assessment Engine.

Sprint 12A — Unified SOC Investigation & Security Case Management.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.security_investigation import (
    SecurityInvestigationCase,
    InvestigationImpactAssessment,
    IMPACT_DOMAIN_PREFIX,
    compute_canonical_hash,
)


IMPACT_WEIGHT_MAP = {
    "CRITICAL": 1.0,
    "HIGH": 0.75,
    "MODERATE": 0.50,
    "LOW": 0.25,
    "NONE": 0.0,
}


class InvestigationImpactService:
    """
    Evaluates multi-dimensional security impact with deterministic mathematical weights.
    """

    @staticmethod
    def calculate_impact_score(
        confidentiality: str = "NONE",
        integrity: str = "NONE",
        availability: str = "NONE",
        business: str = "NONE",
        compliance: str = "NONE",
    ) -> Tuple[float, str]:
        """
        Calculates composite impact score (0.0 - 100.0) and overall classification.
        Weights:
        - Confidentiality: 25.0 max
        - Integrity: 25.0 max
        - Availability: 20.0 max
        - Business: 15.0 max
        - Compliance: 15.0 max
        """
        c_wt = IMPACT_WEIGHT_MAP.get(confidentiality.upper().strip(), 0.0)
        i_wt = IMPACT_WEIGHT_MAP.get(integrity.upper().strip(), 0.0)
        a_wt = IMPACT_WEIGHT_MAP.get(availability.upper().strip(), 0.0)
        b_wt = IMPACT_WEIGHT_MAP.get(business.upper().strip(), 0.0)
        comp_wt = IMPACT_WEIGHT_MAP.get(compliance.upper().strip(), 0.0)

        score = round((c_wt * 25.0) + (i_wt * 25.0) + (a_wt * 20.0) + (b_wt * 15.0) + (comp_wt * 15.0), 1)
        score = max(0.0, min(100.0, score))

        if score >= 80.0 or c_wt == 1.0 or i_wt == 1.0 or a_wt == 1.0:
            overall = "CRITICAL"
        elif score >= 55.0:
            overall = "HIGH"
        elif score >= 30.0:
            overall = "MODERATE"
        else:
            overall = "LOW"

        return score, overall

    @staticmethod
    def assess_impact(
        db: Session,
        case_id: str,
        confidentiality: str = "NONE",
        integrity: str = "NONE",
        availability: str = "NONE",
        business: str = "NONE",
        compliance: str = "NONE",
        assessment_notes: str = "",
        assessed_by: str = "SYSTEM",
    ) -> InvestigationImpactAssessment:
        case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found.")

        score, overall = InvestigationImpactService.calculate_impact_score(
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability,
            business=business,
            compliance=compliance,
        )

        assessment = (
            db.query(InvestigationImpactAssessment)
            .filter(InvestigationImpactAssessment.case_id == case_id)
            .first()
        )

        if assessment:
            assessment.confidentiality_impact = confidentiality.upper().strip()
            assessment.integrity_impact = integrity.upper().strip()
            assessment.availability_impact = availability.upper().strip()
            assessment.business_impact = business.upper().strip()
            assessment.compliance_impact = compliance.upper().strip()
            assessment.impact_score = score
            assessment.overall_impact = overall
            assessment.assessment_notes = assessment_notes
            assessment.assessed_by = assessed_by
            assessment.assessment_hash = assessment.compute_impact_hash()
            db.flush()
            return assessment

        assessment = InvestigationImpactAssessment(
            case_id=case_id,
            confidentiality_impact=confidentiality.upper().strip(),
            integrity_impact=integrity.upper().strip(),
            availability_impact=availability.upper().strip(),
            business_impact=business.upper().strip(),
            compliance_impact=compliance.upper().strip(),
            impact_score=score,
            overall_impact=overall,
            assessment_notes=assessment_notes,
            assessed_by=assessed_by,
            assessment_hash="",
        )
        assessment.assessment_hash = assessment.compute_impact_hash()
        db.add(assessment)
        db.flush()
        return assessment
