"""
services/detection_trust_alert_service.py
-----------------------------------------
Service for managing Detection Trust Alerts generated from rule trust evaluations.

Sprint 6B — Detection Rule Trust Evaluation & Semantic Drift Binding.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.detection_rule_trust import DetectionRuleTrustEvaluation, DetectionTrustAlert


class DetectionTrustAlertService:
    """Service managing detection trust alert lifecycle, deduplication, and triage."""

    @staticmethod
    def determine_alert_attributes(
        trust_status: str,
        is_protected_field: bool,
        canonical_field: str,
    ) -> Optional[Tuple[str, str, str]]:
        """
        Determine (alert_type, severity, description) based on trust status and protected field escalation.

        Alert Severity Matrix:
        - TRUSTED: No alert (returns None)
        - DEGRADED: LOW (escalated to MEDIUM if protected field)
        - AT_RISK: HIGH (escalated to CRITICAL if protected field)
        - INVALID: CRITICAL
        - UNKNOWN: MEDIUM (escalated to HIGH if protected field)

        Returns None if TRUSTED.
        """
        if trust_status == "TRUSTED":
            return None

        if trust_status == "DEGRADED":
            alert_type = "RULE_TRUST_DEGRADED"
            severity = "MEDIUM" if is_protected_field else "LOW"
            desc = (
                f"Detection rule trust degraded on canonical field '{canonical_field}' "
                f"due to low-risk or compatible semantic variance."
            )
            if is_protected_field:
                desc += " (Elevated: Field is a protected semantic asset)."
            return (alert_type, severity, desc)

        if trust_status == "AT_RISK":
            alert_type = "RULE_AT_RISK"
            severity = "CRITICAL" if is_protected_field else "HIGH"
            desc = (
                f"Detection rule is AT RISK on canonical field '{canonical_field}' "
                f"due to ambiguous semantic drift or moderate semantic risk."
            )
            if is_protected_field:
                desc += " (CRITICAL Escalation: Field is a protected security-sensitive asset)."
            return (alert_type, severity, desc)

        if trust_status == "INVALID":
            alert_type = (
                "CRITICAL_SEMANTIC_DEPENDENCY" if is_protected_field else "RULE_INVALIDATED"
            )
            severity = "CRITICAL"
            desc = (
                f"Detection rule invalidated on canonical field '{canonical_field}' "
                f"due to incompatible semantic mapping, unmapped values, or policy conflict."
            )
            return (alert_type, severity, desc)

        if trust_status == "UNKNOWN":
            alert_type = "UNKNOWN_DEPENDENCY"
            severity = "HIGH" if is_protected_field else "MEDIUM"
            desc = (
                f"Detection rule trust cannot be determined for canonical field '{canonical_field}'. "
                f"Zero Trust applies: UNKNOWN is treated as potentially unsafe."
            )
            return (alert_type, severity, desc)

        return None

    @classmethod
    def generate_alert_if_needed(
        cls,
        db: Session,
        evaluation: DetectionRuleTrustEvaluation,
        is_protected_field: bool = False,
    ) -> Optional[DetectionTrustAlert]:
        """
        Generate a DetectionTrustAlert for a non-TRUSTED evaluation if an active
        open alert does not already cover this condition.
        """
        attrs = cls.determine_alert_attributes(
            trust_status=evaluation.trust_status,
            is_protected_field=is_protected_field,
            canonical_field=evaluation.canonical_field,
        )
        if not attrs:
            return None

        alert_type, severity, description = attrs

        # Check for existing open alert for the same rule and affected field
        existing_alert = (
            db.query(DetectionTrustAlert)
            .filter(
                DetectionTrustAlert.rule_id == evaluation.rule_id,
                DetectionTrustAlert.affected_field == evaluation.canonical_field,
                DetectionTrustAlert.status == "OPEN",
            )
            .first()
        )

        if existing_alert:
            # Update existing open alert with latest evaluation info
            existing_alert.evaluation_id = evaluation.evaluation_id
            existing_alert.trust_status = evaluation.trust_status
            existing_alert.trust_score = evaluation.trust_score
            existing_alert.severity = severity
            existing_alert.alert_type = alert_type
            existing_alert.description = description
            if evaluation.drift_alert_id:
                existing_alert.drift_alert_id = evaluation.drift_alert_id
            db.commit()
            db.refresh(existing_alert)
            return existing_alert

        # Create new alert
        alert = DetectionTrustAlert(
            rule_id=evaluation.rule_id,
            evaluation_id=evaluation.evaluation_id,
            drift_alert_id=evaluation.drift_alert_id,
            alert_type=alert_type,
            severity=severity,
            status="OPEN",
            description=description,
            affected_field=evaluation.canonical_field,
            trust_status=evaluation.trust_status,
            trust_score=evaluation.trust_score,
            created_at=datetime.now(timezone.utc),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def list_alerts(
        db: Session,
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        alert_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[DetectionTrustAlert]:
        """Query detection trust alerts with optional filters and pagination."""
        query = db.query(DetectionTrustAlert)
        if rule_id:
            query = query.filter(DetectionTrustAlert.rule_id == rule_id)
        if severity:
            query = query.filter(DetectionTrustAlert.severity == severity.upper())
        if status:
            query = query.filter(DetectionTrustAlert.status == status.upper())
        if alert_type:
            query = query.filter(DetectionTrustAlert.alert_type == alert_type.upper())
        return query.order_by(DetectionTrustAlert.created_at.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_alert_by_id(db: Session, alert_id: str) -> Optional[DetectionTrustAlert]:
        """Fetch a single alert by its unique alert_id."""
        return (
            db.query(DetectionTrustAlert)
            .filter(DetectionTrustAlert.alert_id == alert_id)
            .first()
        )

    @staticmethod
    def update_alert_status(
        db: Session,
        alert_id: str,
        new_status: str,
    ) -> Optional[DetectionTrustAlert]:
        """Update triage status for a trust alert ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')."""
        alert = (
            db.query(DetectionTrustAlert)
            .filter(DetectionTrustAlert.alert_id == alert_id)
            .first()
        )
        if not alert:
            return None

        alert.status = new_status.upper()
        if new_status.upper() in ("ACKNOWLEDGED", "RESOLVED"):
            alert.resolved_at = datetime.now(timezone.utc)
        else:
            alert.resolved_at = None

        db.commit()
        db.refresh(alert)
        return alert
