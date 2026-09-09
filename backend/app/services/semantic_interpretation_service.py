"""
services/semantic_interpretation_service.py
-------------------------------------------
Core engine for Vendor-Scoped Semantic Interpretation, Drift Detection,
and Explainable Traceability.

Sprint 3B — Semantic Interpretation Engine & Semantic Drift Detection.
Strictly separates structural parsing from vendor-scoped semantic interpretation.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session, joinedload

from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.semantic_interpretation import (
    SemanticDriftAlert,
    SemanticInterpretation,
)
from app.models.semantic_policy import (
    ProtectedSemanticField,
    SemanticPolicy,
    SemanticPolicyRule,
)
from app.models.source_profile import SourceProfile

logger = logging.getLogger("sentinel.services.semantic_interpretation")


class SemanticInterpretationService:
    """
    Executes vendor-scoped semantic policy evaluation, deterministic confidence scoring,
    explainable reasoning generation, and defensive drift detection.
    """

    @staticmethod
    def resolve_vendor_context(
        normalized: NormalizedEvent,
        profile: Optional[SourceProfile] = None,
    ) -> Tuple[str, str]:
        """
        Deterministically resolves the vendor name and source profile ID from normalized event metadata.
        """
        source_profile_id = normalized.source_profile_id or (profile.source_profile_id if profile else "sp_firewall_syslog")
        raw_data = normalized.raw_data or {}
        raw_vendor = raw_data.get("vendor", "").strip()

        source_name_lower = (normalized.source_name or "").lower()

        # 1. Explicit raw vendor payload
        if raw_vendor:
            return raw_vendor, source_profile_id

        # 2. Heuristics from source name or explicit profile linkage
        if "demo" in source_name_lower or source_profile_id == "sp_demo_vendor":
            return "Demo Vendor", source_profile_id
        if "cisco" in source_name_lower or "asa" in source_name_lower:
            return "Cisco ASA", source_profile_id
        if "conflict" in source_name_lower:
            return "Conflict Vendor", source_profile_id
        if "auth" in source_name_lower or source_profile_id == "sp_auth_json":
            return "Generic Auth Provider", source_profile_id
        if "system" in source_name_lower or source_profile_id == "sp_process_csv":
            return "Generic System Provider", source_profile_id

        # Fallback to Cisco ASA for firewall syslog without explicit vendor
        if source_profile_id == "sp_firewall_syslog":
            return "Cisco ASA", source_profile_id

        # Default to normalized source_name
        return normalized.source_name or "Generic Vendor", source_profile_id

    @staticmethod
    def get_active_policy_for_vendor(
        db: Session,
        vendor_name: str,
        source_profile_id: str,
    ) -> Optional[SemanticPolicy]:
        """
        Finds the unique ACTIVE semantic policy scoped to the specified vendor and source profile.
        Strictly prevents global or cross-vendor fallback.
        """
        # Exact match on vendor_name and status ACTIVE
        policy = (
            db.query(SemanticPolicy)
            .options(joinedload(SemanticPolicy.rules))
            .filter(
                SemanticPolicy.status == "ACTIVE",
                SemanticPolicy.vendor_name == vendor_name,
            )
            .order_by(SemanticPolicy.version.desc())
            .first()
        )

        if not policy:
            # Secondary check matching source_profile_id if vendor_name was matched by family
            policy = (
                db.query(SemanticPolicy)
                .options(joinedload(SemanticPolicy.rules))
                .filter(
                    SemanticPolicy.status == "ACTIVE",
                    SemanticPolicy.source_profile_id == source_profile_id,
                )
                .order_by(SemanticPolicy.version.desc())
                .first()
            )

        return policy

    @classmethod
    def interpret_normalized_event(
        cls,
        db: Session,
        normalized_event_id: str,
    ) -> SemanticInterpretation:
        """
        Main interpretation pipeline:
        1. Retrieve normalized event and raw evidence link.
        2. Identify source profile and vendor context.
        3. Retrieve active vendor-scoped semantic policy.
        4. Match policy rules against extracted source field values.
        5. Compute deterministic confidence score and human-readable explanation.
        6. Detect semantic drift (unmapped, ambiguous, conflict, protected field risk).
        7. Persist interpretation and alerts separately without mutating normalized event or raw evidence.
        """
        # 1. Retrieve normalized event
        normalized = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.normalized_event_id == normalized_event_id)
            .first()
        )
        if not normalized:
            raise ValueError(f"Normalized event '{normalized_event_id}' not found.")

        # Retrieve source profile
        profile = None
        if normalized.source_profile_id:
            profile = (
                db.query(SourceProfile)
                .filter(SourceProfile.source_profile_id == normalized.source_profile_id)
                .first()
            )

        # 2. Resolve vendor context
        vendor_name, source_profile_id = cls.resolve_vendor_context(normalized, profile)

        # 3. Retrieve active semantic policy
        policy = cls.get_active_policy_for_vendor(db, vendor_name, source_profile_id)

        # Idempotency check: return existing interpretation if already processed for this normalized event & policy
        policy_id = policy.policy_id if policy else None
        policy_version = policy.version if policy else None

        existing_interp = (
            db.query(SemanticInterpretation)
            .options(joinedload(SemanticInterpretation.drift_alerts))
            .filter(
                SemanticInterpretation.normalized_event_id == normalized_event_id,
                SemanticInterpretation.policy_id == policy_id,
                SemanticInterpretation.policy_version == policy_version,
            )
            .first()
        )
        if existing_interp:
            logger.info(
                f"Returning existing interpretation {existing_interp.interpretation_id} for normalized event {normalized_event_id}"
            )
            return existing_interp

        # Query protected semantic fields for risk evaluation
        protected_fields_map = {
            pf.field_name: pf for pf in db.query(ProtectedSemanticField).all()
        }

        # 4. Extract semantic values to evaluate
        source_field = "action"
        raw_dict = normalized.raw_data or {}
        source_value = raw_dict.get("action") or normalized.action or "UNKNOWN_ACTION"
        if isinstance(source_value, str):
            source_value = source_value.strip()
        canonical_field = "action.result"

        # Check for policy rules matching source_field and source_value
        matched_rules: List[SemanticPolicyRule] = []
        if policy and policy.rules:
            for r in policy.rules:
                if (
                    r.source_field.lower() == source_field.lower()
                    and r.source_value.upper() == source_value.upper()
                ):
                    matched_rules.append(r)

        # Evaluate rules and detect drift
        drift_alerts_to_create: List[Dict[str, Any]] = []
        confidence_reasons: List[str] = []
        confidence_score = 1.0
        interpretation_status = "INTERPRETED"
        equivalence_classification = None
        risk_level = "LOW"
        interpreted_value = None
        explanation = ""

        # Case A: No Active Policy Found
        if not policy:
            interpretation_status = "UNMAPPED"
            risk_level = "MEDIUM"
            confidence_score = 0.50
            confidence_reasons.append("NO_ACTIVE_POLICY: -0.50")
            explanation = (
                f"No active vendor-scoped semantic policy exists for vendor '{vendor_name}' "
                f"and source profile '{source_profile_id}'. No global fallback mapping is allowed."
            )
            drift_alerts_to_create.append({
                "drift_type": "UNMAPPED_VALUE",
                "severity": "MEDIUM",
                "description": f"No active semantic policy available for vendor '{vendor_name}'.",
                "expected_value": "Active Vendor Policy",
                "observed_value": source_value,
            })

        # Case B: Conflicting rules detected
        elif len(matched_rules) > 1 and len({r.canonical_value for r in matched_rules}) > 1:
            interpretation_status = "CONFLICT"
            risk_level = "HIGH"
            confidence_score = 0.0
            conflicting_values = [r.canonical_value for r in matched_rules]
            confidence_reasons.append(f"POLICY_CONFLICT: Multiple canonical values {conflicting_values}")
            explanation = (
                f"Conflicting semantic rules detected under policy '{policy.policy_id}' for source value '{source_value}'. "
                f"Rule candidates yielded distinct canonical values: {conflicting_values}. Engine refuses silent resolution."
            )
            drift_alerts_to_create.append({
                "drift_type": "POLICY_CONFLICT",
                "severity": "HIGH",
                "description": f"Conflicting semantic rules found for source value '{source_value}' in policy '{policy.policy_id}'.",
                "expected_value": "Deterministic Single Rule",
                "observed_value": str(conflicting_values),
            })

        # Case C: No rule matched within active policy
        elif len(matched_rules) == 0:
            interpretation_status = "UNMAPPED"
            risk_level = "MEDIUM"
            confidence_score = 0.50
            confidence_reasons.append("UNMAPPED_VALUE: -0.50")
            explanation = (
                f"No active vendor-scoped semantic rule matched source value '{source_value}' "
                f"for vendor '{vendor_name}' under policy '{policy.policy_id}'."
            )
            drift_alerts_to_create.append({
                "drift_type": "UNMAPPED_VALUE",
                "severity": "MEDIUM",
                "description": f"Source value '{source_value}' has no defined rule in policy '{policy.policy_id}'.",
                "expected_value": "Mapped Semantic Rule",
                "observed_value": source_value,
            })

        # Case D: Exactly 1 valid rule matched
        else:
            rule = matched_rules[0]
            canonical_field = rule.canonical_field
            interpreted_value = rule.canonical_value
            equivalence_classification = rule.equivalence_classification
            risk_level = rule.risk_level or "LOW"

            # Compute classification deductions
            if equivalence_classification == "EQUIVALENT":
                pass
            elif equivalence_classification == "COMPATIBLE":
                confidence_score -= 0.10
                confidence_reasons.append("COMPATIBLE_MAPPING: -0.10")
            elif equivalence_classification == "AMBIGUOUS":
                confidence_score -= 0.25
                confidence_reasons.append("AMBIGUOUS_MAPPING: -0.25")
                interpretation_status = "AMBIGUOUS"
                if risk_level == "LOW":
                    risk_level = "MEDIUM"
                drift_alerts_to_create.append({
                    "drift_type": "AMBIGUOUS_MAPPING",
                    "severity": "MEDIUM",
                    "description": (
                        f"Source value '{source_value}' has an ambiguous interpretation '{interpreted_value}' "
                        f"in policy '{policy.policy_id}'. Human review recommended."
                    ),
                    "expected_value": "EQUIVALENT",
                    "observed_value": f"AMBIGUOUS -> {interpreted_value}",
                })
            elif equivalence_classification == "INCOMPATIBLE":
                confidence_score -= 0.40
                confidence_reasons.append("INCOMPATIBLE_MAPPING: -0.40")
                risk_level = "HIGH"
                drift_alerts_to_create.append({
                    "drift_type": "INCOMPATIBLE_MAPPING",
                    "severity": "HIGH",
                    "description": f"Source value '{source_value}' is classified as INCOMPATIBLE in policy '{policy.policy_id}'.",
                    "expected_value": "COMPATIBLE",
                    "observed_value": interpreted_value,
                })

            # Check for Protected Semantic Field Risk
            if canonical_field in protected_fields_map:
                pf = protected_fields_map[canonical_field]
                if equivalence_classification in ["AMBIGUOUS", "INCOMPATIBLE"]:
                    confidence_score -= 0.15
                    confidence_reasons.append(f"PROTECTED_FIELD_RISK ({canonical_field}): -0.15")
                    risk_level = "HIGH"
                    drift_alerts_to_create.append({
                        "drift_type": "PROTECTED_FIELD_RISK",
                        "severity": "HIGH",
                        "description": (
                            f"Protected semantic field '{canonical_field}' ({pf.criticality}) was mapped with "
                            f"classification '{equivalence_classification}'. Elevated security alert generated."
                        ),
                        "expected_value": f"{canonical_field} (EQUIVALENT/HIGH_CONFIDENCE)",
                        "observed_value": f"{interpreted_value} ({equivalence_classification})",
                    })

            # Clamp confidence score
            confidence_score = max(0.0, min(1.0, round(confidence_score, 2)))

            # Build human-readable explanation
            explanation = (
                f"Vendor context '{vendor_name}' matched active policy '{policy.policy_id}' (v{policy.version}). "
                f"Source value '{source_value}' from field '{source_field}' was mapped to canonical field '{canonical_field}' "
                f"with value '{interpreted_value}'. Classification: {equivalence_classification}. "
                f"Semantic confidence: {confidence_score:.2f}."
            )

        # 5. Persist Interpretation record
        interpretation = SemanticInterpretation(
            interpretation_id=f"interp_{uuid.uuid4().hex[:16]}",
            normalized_event_id=normalized.normalized_event_id,
            original_event_id=normalized.original_event_id,
            policy_id=policy_id,
            policy_version=policy_version,
            vendor_name=vendor_name,
            source_profile_id=source_profile_id,
            source_field=source_field,
            source_value=source_value,
            canonical_field=canonical_field,
            interpreted_value=interpreted_value,
            equivalence_classification=equivalence_classification,
            risk_level=risk_level,
            interpretation_status=interpretation_status,
            confidence_score=confidence_score,
            confidence_reasons=confidence_reasons,
            explanation=explanation,
        )
        db.add(interpretation)
        db.flush()

        # 6. Persist Linked Drift Alerts
        for alert_data in drift_alerts_to_create:
            alert = SemanticDriftAlert(
                alert_id=f"drift_{uuid.uuid4().hex[:16]}",
                normalized_event_id=normalized.normalized_event_id,
                interpretation_id=interpretation.interpretation_id,
                policy_id=policy_id,
                drift_type=alert_data["drift_type"],
                severity=alert_data["severity"],
                status="OPEN",
                description=alert_data["description"],
                expected_value=alert_data.get("expected_value"),
                observed_value=alert_data.get("observed_value"),
            )
            db.add(alert)

        db.commit()
        db.refresh(interpretation)
        logger.info(
            f"Created semantic interpretation {interpretation.interpretation_id} for {normalized_event_id}: "
            f"status={interpretation_status}, value={interpreted_value}, alerts={len(drift_alerts_to_create)}"
        )
        return interpretation

    @staticmethod
    def list_interpretations(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
        policy_id: Optional[str] = None,
        vendor_name: Optional[str] = None,
    ) -> Tuple[List[SemanticInterpretation], int]:
        """List paginated semantic interpretations with optional filters."""
        query = db.query(SemanticInterpretation).options(joinedload(SemanticInterpretation.drift_alerts))

        if status:
            query = query.filter(SemanticInterpretation.interpretation_status == status)
        if risk_level:
            query = query.filter(SemanticInterpretation.risk_level == risk_level)
        if policy_id:
            query = query.filter(SemanticInterpretation.policy_id == policy_id)
        if vendor_name:
            query = query.filter(SemanticInterpretation.vendor_name == vendor_name)

        total = query.count()
        items = query.order_by(SemanticInterpretation.created_at.desc()).offset(offset).limit(limit).all()
        return items, total

    @staticmethod
    def get_interpretation_by_id(
        db: Session,
        interpretation_id: str,
    ) -> Optional[SemanticInterpretation]:
        """Retrieve a single interpretation record by ID."""
        return (
            db.query(SemanticInterpretation)
            .options(joinedload(SemanticInterpretation.drift_alerts))
            .filter(SemanticInterpretation.interpretation_id == interpretation_id)
            .first()
        )

    @staticmethod
    def list_drift_alerts(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        drift_type: Optional[str] = None,
    ) -> Tuple[List[SemanticDriftAlert], int]:
        """List paginated semantic drift alerts."""
        query = db.query(SemanticDriftAlert)

        if severity:
            query = query.filter(SemanticDriftAlert.severity == severity)
        if status:
            query = query.filter(SemanticDriftAlert.status == status)
        if drift_type:
            query = query.filter(SemanticDriftAlert.drift_type == drift_type)

        total = query.count()
        items = query.order_by(SemanticDriftAlert.detected_at.desc()).offset(offset).limit(limit).all()
        return items, total

    @staticmethod
    def get_drift_alert_by_id(
        db: Session,
        alert_id: str,
    ) -> Optional[SemanticDriftAlert]:
        """Retrieve a single drift alert by ID."""
        return (
            db.query(SemanticDriftAlert)
            .filter(SemanticDriftAlert.alert_id == alert_id)
            .first()
        )

    @staticmethod
    def get_full_semantic_trace(
        db: Session,
        interpretation_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Builds complete end-to-end explainable audit trail:
        Raw Evidence -> Normalized Event -> Source Profile -> Vendor -> Semantic Policy -> Policy Rule -> Interpretation -> Drift Alerts
        """
        interp = (
            db.query(SemanticInterpretation)
            .options(joinedload(SemanticInterpretation.drift_alerts))
            .filter(SemanticInterpretation.interpretation_id == interpretation_id)
            .first()
        )
        if not interp:
            return None

        # 1. Fetch raw event
        raw_event = (
            db.query(IngestedEvent)
            .filter(IngestedEvent.event_id == interp.original_event_id)
            .first()
        )

        # 2. Fetch normalized event
        norm_event = (
            db.query(NormalizedEvent)
            .filter(NormalizedEvent.normalized_event_id == interp.normalized_event_id)
            .first()
        )

        # 3. Fetch source profile
        profile = (
            db.query(SourceProfile)
            .filter(SourceProfile.source_profile_id == interp.source_profile_id)
            .first()
        )

        # 4. Fetch policy
        policy = None
        matched_rule = None
        if interp.policy_id:
            policy = (
                db.query(SemanticPolicy)
                .options(joinedload(SemanticPolicy.rules))
                .filter(SemanticPolicy.policy_id == interp.policy_id)
                .first()
            )
            if policy and policy.rules:
                for r in policy.rules:
                    if (
                        r.source_field.lower() == interp.source_field.lower()
                        and r.source_value.upper() == interp.source_value.upper()
                    ):
                        matched_rule = r.to_dict()
                        break

        return {
            "interpretation_id": interp.interpretation_id,
            "raw_evidence": {
                "event_id": raw_event.event_id if raw_event else interp.original_event_id,
                "source_name": raw_event.source_name if raw_event else "Unknown",
                "source_type": raw_event.source_type if raw_event else "Unknown",
                "file_format": raw_event.file_format if raw_event else "Unknown",
                "raw_content_hash": raw_event.raw_content_hash if raw_event else "Unknown",
                "content_size": raw_event.content_size if raw_event else 0,
                "preserved_at": raw_event.ingested_at.isoformat() if raw_event and raw_event.ingested_at else None,
            },
            "normalized_event": {
                "normalized_event_id": norm_event.normalized_event_id if norm_event else interp.normalized_event_id,
                "class_name": norm_event.class_name if norm_event else "Unknown",
                "activity_name": norm_event.activity_name if norm_event else "Unknown",
                "action": norm_event.action if norm_event else interp.source_value,
                "normalization_status": norm_event.normalization_status if norm_event else "NORMALIZED",
                "normalization_confidence": norm_event.normalization_confidence if norm_event else 1.0,
            },
            "source_profile": {
                "source_profile_id": interp.source_profile_id,
                "profile_name": profile.profile_name if profile else interp.source_profile_id,
                "parser_type": profile.parser_type if profile else "Unknown",
            },
            "vendor": interp.vendor_name,
            "semantic_policy": {
                "policy_id": policy.policy_id,
                "policy_name": policy.policy_name,
                "version": policy.version,
                "status": policy.status,
            } if policy else None,
            "matched_rule": matched_rule,
            "semantic_decision": {
                "canonical_field": interp.canonical_field,
                "interpreted_value": interp.interpreted_value,
                "equivalence_classification": interp.equivalence_classification,
                "risk_level": interp.risk_level,
                "interpretation_status": interp.interpretation_status,
                "confidence_score": interp.confidence_score,
                "confidence_reasons": interp.confidence_reasons,
                "explanation": interp.explanation,
            },
            "drift_alerts": [a.to_dict() for a in interp.drift_alerts],
        }
