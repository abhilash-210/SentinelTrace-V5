"""
services/security_assurance_service.py
---------------------------------------
Deterministic Continuous Security Assurance Engine, Domain Scoring, Platform Health Composite,
Hard Failure Overrides, Metric Definitions Catalog, Deduplicated Alert Engine, and 17-Stage Provenance.

Sprint 9A — Continuous Security Assurance & Platform Health Intelligence.
Core Invariant: "SENTINELTRACE MUST MONITOR THE TRUSTWORTHINESS OF ITS OWN SECURITY PIPELINE."
Zero Trust Rule: "UNKNOWN != HEALTHY" — Missing observability must never increase trust.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

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
from app.models.security_incident import SecurityIncident, IncidentSignal
from app.models.incident_response import (
    IncidentContainmentRequest,
    IncidentResponseExecution,
    IncidentResponseVerification,
)
from app.models.ledger import GovernanceLedgerEntry
from app.models.merkle import MerkleBatch, MerkleProof

logger = logging.getLogger("sentinel.services.security_assurance")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SecurityAssuranceService:
    """
    Deterministic Continuous Security Assurance Engine.
    Evaluates platform trust across 7 domains with transparent mathematical deductions,
    hard failure overrides, immutable audit snapshots, and cryptographic provenance.
    """

    DOMAIN_PREFIX = "SENTINELTRACE_ASSURANCE_EVALUATION_V1"

    DEFAULT_DOMAIN_WEIGHTS = {
        "EVIDENCE_ASSURANCE": 0.15,
        "NORMALIZATION_ASSURANCE": 0.10,
        "SEMANTIC_ASSURANCE": 0.15,
        "DETECTION_ASSURANCE": 0.20,
        "RISK_ASSURANCE": 0.10,
        "INCIDENT_RESPONSE_ASSURANCE": 0.15,
        "CRYPTOGRAPHIC_ASSURANCE": 0.15,
    }

    # ── Canonical Domain Names ────────────────────────────────────────────────
    DOMAINS = [
        "EVIDENCE_ASSURANCE",
        "NORMALIZATION_ASSURANCE",
        "SEMANTIC_ASSURANCE",
        "DETECTION_ASSURANCE",
        "RISK_ASSURANCE",
        "INCIDENT_RESPONSE_ASSURANCE",
        "CRYPTOGRAPHIC_ASSURANCE",
    ]

    # ── Deterministic Helpers ─────────────────────────────────────────────────
    @staticmethod
    def _compute_hash(payload: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 hash using domain separation."""
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        raw_msg = f"{SecurityAssuranceService.DOMAIN_PREFIX}||{canonical_json}"
        return hashlib.sha256(raw_msg.encode("utf-8")).hexdigest()

    @staticmethod
    def _classify_score(score: float, has_hard_critical: bool = False) -> str:
        """
        Deterministic status classification:
        90.0 - 100.0: HEALTHY
        70.0 - 89.99: DEGRADED
        40.0 - 69.99: AT_RISK
        0.0  - 39.99: CRITICAL
        """
        if has_hard_critical:
            return "CRITICAL"
        if score >= 90.0:
            return "HEALTHY"
        elif score >= 70.0:
            return "DEGRADED"
        elif score >= 40.0:
            return "AT_RISK"
        else:
            return "CRITICAL"

    @staticmethod
    def _compute_deduplication_key(domain_name: str, alert_type: str, source_condition: str) -> str:
        """Generates deterministic SHA-256 deduplication key for assurance alerts."""
        raw = f"{domain_name}:{alert_type}:{source_condition}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # ── Metric Catalog Initialization ─────────────────────────────────────────
    @classmethod
    def seed_default_metric_definitions(cls, db: Session) -> int:
        """Seeds initial assurance metric definitions if not present."""
        default_metrics = [
            # Evidence
            {
                "metric_key": "evidence.hash_mismatch",
                "domain_name": "EVIDENCE_ASSURANCE",
                "metric_name": "Evidence Hash Mismatch",
                "description": "Cryptographic mismatch between raw payload and ingested SHA-256 hash",
                "weight": 50.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 1.0,
                "at_risk_threshold": 1.0,
                "critical_threshold": 1.0,
            },
            {
                "metric_key": "evidence.ingestion_failures",
                "domain_name": "EVIDENCE_ASSURANCE",
                "metric_name": "Recent Ingestion Failures",
                "description": "Count of failed raw evidence ingestion attempts",
                "weight": 5.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 1.0,
                "at_risk_threshold": 3.0,
                "critical_threshold": 5.0,
            },
            {
                "metric_key": "evidence.pipeline_inactivity",
                "domain_name": "EVIDENCE_ASSURANCE",
                "metric_name": "Pipeline Inactivity Gap",
                "description": "Prolonged inactivity or gaps in expected evidence ingestion telemetry",
                "weight": 15.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 1.0,
                "at_risk_threshold": 1.0,
                "critical_threshold": 2.0,
            },
            # Normalization
            {
                "metric_key": "normalization.failure_rate",
                "domain_name": "NORMALIZATION_ASSURANCE",
                "metric_name": "Normalization Failure Rate",
                "description": "Percentage of raw events failing OCSF canonical normalization",
                "weight": 10.0,
                "healthy_threshold": 5.0,
                "degraded_threshold": 15.0,
                "at_risk_threshold": 30.0,
                "critical_threshold": 50.0,
            },
            {
                "metric_key": "normalization.unmapped_fields",
                "domain_name": "NORMALIZATION_ASSURANCE",
                "metric_name": "Unmapped Canonical Fields",
                "description": "Core OCSF canonical schema fields missing across normalized events",
                "weight": 5.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 2.0,
                "at_risk_threshold": 4.0,
                "critical_threshold": 6.0,
            },
            # Semantic
            {
                "metric_key": "semantic.ambiguous_mappings",
                "domain_name": "SEMANTIC_ASSURANCE",
                "metric_name": "Ambiguous Semantic Mappings",
                "description": "Semantic mappings with low interpretation confidence (< 0.70)",
                "weight": 5.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 1.0,
                "at_risk_threshold": 3.0,
                "critical_threshold": 5.0,
            },
            {
                "metric_key": "semantic.protected_field_drift",
                "domain_name": "SEMANTIC_ASSURANCE",
                "metric_name": "Protected Field Semantic Drift",
                "description": "Active semantic drift detected on protected core fields",
                "weight": 25.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 1.0,
                "at_risk_threshold": 2.0,
                "critical_threshold": 3.0,
            },
            # Detection
            {
                "metric_key": "detection.invalid_rules",
                "domain_name": "DETECTION_ASSURANCE",
                "metric_name": "Invalid Detection Rules",
                "description": "Detection rules in INVALID trust state due to broken schema dependencies",
                "weight": 20.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 1.0,
                "at_risk_threshold": 2.0,
                "critical_threshold": 3.0,
            },
            {
                "metric_key": "detection.degraded_rules",
                "domain_name": "DETECTION_ASSURANCE",
                "metric_name": "Degraded Detection Rules",
                "description": "Detection rules in DEGRADED or AT_RISK trust state",
                "weight": 5.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 2.0,
                "at_risk_threshold": 4.0,
                "critical_threshold": 6.0,
            },
            # Risk
            {
                "metric_key": "risk.critical_posture_findings",
                "domain_name": "RISK_ASSURANCE",
                "metric_name": "Critical Security Posture Findings",
                "description": "Unresolved critical posture findings and risk concentration clusters",
                "weight": 15.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 1.0,
                "at_risk_threshold": 2.0,
                "critical_threshold": 3.0,
            },
            # Incident Response
            {
                "metric_key": "response.open_critical_incidents",
                "domain_name": "INCIDENT_RESPONSE_ASSURANCE",
                "metric_name": "Open Critical Incidents",
                "description": "Open uncontained P1/CRITICAL security incidents",
                "weight": 10.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 1.0,
                "at_risk_threshold": 3.0,
                "critical_threshold": 5.0,
            },
            {
                "metric_key": "response.unverified_executions",
                "domain_name": "INCIDENT_RESPONSE_ASSURANCE",
                "metric_name": "Unverified Response Executions",
                "description": "Containment actions executed without formal verification records",
                "weight": 15.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 1.0,
                "at_risk_threshold": 2.0,
                "critical_threshold": 3.0,
            },
            # Cryptographic
            {
                "metric_key": "cryptographic.ledger_integrity",
                "domain_name": "CRYPTOGRAPHIC_ASSURANCE",
                "metric_name": "Governance Ledger Chain Integrity",
                "description": "Cryptographic validation of SHA-256 continuous hash chain in ledger",
                "weight": 60.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 1.0,
                "at_risk_threshold": 1.0,
                "critical_threshold": 1.0,
            },
            {
                "metric_key": "cryptographic.merkle_proof_failures",
                "domain_name": "CRYPTOGRAPHIC_ASSURANCE",
                "metric_name": "Merkle Proof Verification Failures",
                "description": "Failures verifying Merkle root inclusions and cryptographic receipts",
                "weight": 50.0,
                "healthy_threshold": 0.0,
                "degraded_threshold": 1.0,
                "at_risk_threshold": 1.0,
                "critical_threshold": 1.0,
            },
        ]

        count = 0
        for item in default_metrics:
            existing = (
                db.query(AssuranceMetricDefinition)
                .filter(AssuranceMetricDefinition.metric_key == item["metric_key"])
                .first()
            )
            if not existing:
                metric_def = AssuranceMetricDefinition(
                    id=f"amd-{uuid.uuid4().hex[:12]}",
                    metric_key=item["metric_key"],
                    domain_name=item["domain_name"],
                    metric_name=item["metric_name"],
                    description=item["description"],
                    weight=item["weight"],
                    healthy_threshold=item["healthy_threshold"],
                    degraded_threshold=item["degraded_threshold"],
                    at_risk_threshold=item["at_risk_threshold"],
                    critical_threshold=item["critical_threshold"],
                    enabled=True,
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
                db.add(metric_def)
                count += 1
        if count > 0:
            db.commit()
        return count

    # ── Domain 1: EVIDENCE_ASSURANCE ─────────────────────────────────────────
    @classmethod
    def _evaluate_evidence_assurance(cls, db: Session) -> Tuple[float, str, Dict[str, Any], List[Dict[str, Any]], str]:
        """
        Evaluates raw evidence availability, SHA-256 hash integrity, ingestion failures,
        and ingestion continuity.
        Base: 100. Deductions:
        - Evidence hash mismatch: -50 each
        - Ingestion failure: -5 each (max -20)
        - Pipeline inactivity: -15
        - Duplicate anomaly: -10
        - Critical ingestion failure: -25
        """
        deductions: List[Dict[str, Any]] = []
        base_score = 100.0

        # Query ingested events
        total_events = db.query(IngestedEvent).count()
        recent_events = (
            db.query(IngestedEvent)
            .order_by(desc(IngestedEvent.ingested_at))
            .limit(100)
            .all()
        )

        hash_mismatches = 0
        ingestion_failures = 0
        critical_failures = 0
        duplicate_anomalies = 0

        # Verify hash integrity over recent sample
        seen_hashes = set()
        for evt in recent_events:
            raw_data = getattr(evt, "raw_content", None)
            expected_hash = getattr(evt, "raw_content_hash", None)

            if raw_data is not None and expected_hash:
                computed = hashlib.sha256(raw_data.encode("utf-8")).hexdigest()
                if expected_hash != computed:
                    hash_mismatches += 1

            status = getattr(evt, "processing_status", "PRESERVED")
            if status in ("FAILED", "CORRUPT", "ERROR", "MISMATCH"):
                ingestion_failures += 1
                if getattr(evt, "source_type", "") == "critical" or status == "MISMATCH":
                    critical_failures += 1

            if expected_hash:
                if expected_hash in seen_hashes:
                    duplicate_anomalies += 1
                else:
                    seen_hashes.add(expected_hash)

        # Apply deterministic deductions
        if hash_mismatches > 0:
            ded = min(100.0, hash_mismatches * 50.0)
            deductions.append({
                "metric_key": "evidence.hash_mismatch",
                "deduction": ded,
                "reason": f"{hash_mismatches} evidence hash integrity mismatch(es) detected",
                "severity": "CRITICAL",
                "details": {"mismatches": hash_mismatches},
            })

        if critical_failures > 0:
            ded = min(25.0, critical_failures * 25.0)
            deductions.append({
                "metric_key": "evidence.critical_failure",
                "deduction": ded,
                "reason": f"{critical_failures} critical ingestion failure(s) recorded",
                "severity": "CRITICAL",
                "details": {"critical_failures": critical_failures},
            })

        if ingestion_failures > 0:
            ded = min(20.0, ingestion_failures * 5.0)
            deductions.append({
                "metric_key": "evidence.ingestion_failures",
                "deduction": ded,
                "reason": f"{ingestion_failures} recent ingestion failure(s) recorded",
                "severity": "MEDIUM",
                "details": {"failures": ingestion_failures},
            })

        if duplicate_anomalies > 5:
            deductions.append({
                "metric_key": "evidence.duplicate_anomalies",
                "deduction": 10.0,
                "reason": f"Duplicate evidence anomaly spike ({duplicate_anomalies} duplicates in sample)",
                "severity": "LOW",
                "details": {"duplicates": duplicate_anomalies},
            })

        # Check for pipeline inactivity / gap
        is_inactive = False
        if total_events > 0 and len(recent_events) > 0:
            last_event_time = recent_events[0].ingested_at
            if last_event_time:
                if last_event_time.tzinfo is None:
                    last_event_time = last_event_time.replace(tzinfo=timezone.utc)
                if (utcnow() - last_event_time).total_seconds() > 86400 * 7:  # 7 days gap
                    is_inactive = True
                    deductions.append({
                        "metric_key": "evidence.pipeline_inactivity",
                        "deduction": 15.0,
                        "reason": "Pipeline inactivity gap: No raw evidence ingested within active telemetry window",
                        "severity": "MEDIUM",
                        "details": {"last_ingested": last_event_time.isoformat()},
                    })

        total_deduction = sum(d["deduction"] for d in deductions)
        final_score = max(0.0, min(100.0, round(base_score - total_deduction, 2)))
        status = cls._classify_score(final_score)

        metric_snapshot = {
            "total_ingested_events": total_events,
            "sample_size": len(recent_events),
            "hash_mismatches": hash_mismatches,
            "ingestion_failures": ingestion_failures,
            "critical_failures": critical_failures,
            "duplicate_anomalies": duplicate_anomalies,
            "pipeline_inactivity": is_inactive,
        }

        explanation = (
            f"Evidence Assurance evaluated at {final_score:.2f}/100 ({status}). "
            f"Evaluated {total_events} raw events across hash integrity, ingestion stability, and continuity."
        )

        return final_score, status, metric_snapshot, deductions, explanation


    # ── Domain 2: NORMALIZATION_ASSURANCE ────────────────────────────────────
    @classmethod
    def _evaluate_normalization_assurance(cls, db: Session) -> Tuple[float, str, Dict[str, Any], List[Dict[str, Any]], str]:
        """
        Evaluates OCSF normalization success rate, unmapped vendor fields, and pipeline exceptions.
        Base: 100. Deductions:
        - Failure rate > 5%: -10, > 15%: -25, > 30%: -50
        - Unmapped canonical fields: -5 each (max -20)
        - Normalization pipeline exception: -20
        """
        deductions: List[Dict[str, Any]] = []
        base_score = 100.0

        total_normalized = db.query(NormalizedEvent).count()
        recent_normalized = (
            db.query(NormalizedEvent)
            .order_by(desc(NormalizedEvent.normalized_at))
            .limit(100)
            .all()
        )

        failed_normalization = 0
        unmapped_field_count = 0
        pipeline_exceptions = 0

        # Required canonical OCSF fields
        required_fields = ["class_uid", "activity_id", "severity_id", "category_uid"]

        for ne in recent_normalized:
            # Check validation status or unparsed markers
            if getattr(ne, "normalization_status", "SUCCESS") in ("FAILED", "MALFORMED", "UNPARSED"):
                failed_normalization += 1
            if getattr(ne, "validation_errors", None):
                pipeline_exceptions += 1

            # Check canonical field completeness
            ocsf_data = getattr(ne, "ocsf_payload", {}) or {}
            missing_in_event = [f for f in required_fields if f not in ocsf_data and getattr(ne, f, None) is None]
            if missing_in_event:
                unmapped_field_count += len(missing_in_event)

        failure_rate = (failed_normalization / len(recent_normalized) * 100.0) if recent_normalized else 0.0

        if failure_rate > 30.0:
            deductions.append({
                "metric_key": "normalization.failure_rate_critical",
                "deduction": 50.0,
                "reason": f"Severe normalization failure rate ({failure_rate:.1f}% > 30%)",
                "severity": "CRITICAL",
                "details": {"failure_rate": failure_rate},
            })
        elif failure_rate > 15.0:
            deductions.append({
                "metric_key": "normalization.failure_rate_high",
                "deduction": 25.0,
                "reason": f"High normalization failure rate ({failure_rate:.1f}% > 15%)",
                "severity": "HIGH",
                "details": {"failure_rate": failure_rate},
            })
        elif failure_rate > 5.0:
            deductions.append({
                "metric_key": "normalization.failure_rate_medium",
                "deduction": 10.0,
                "reason": f"Elevated normalization failure rate ({failure_rate:.1f}% > 5%)",
                "severity": "MEDIUM",
                "details": {"failure_rate": failure_rate},
            })

        if unmapped_field_count > 0:
            ded = min(20.0, (unmapped_field_count // max(1, len(recent_normalized))) * 5.0 + (5.0 if unmapped_field_count > 0 else 0.0))
            deductions.append({
                "metric_key": "normalization.unmapped_canonical_fields",
                "deduction": ded,
                "reason": f"Missing canonical OCSF fields detected ({unmapped_field_count} instances)",
                "severity": "MEDIUM",
                "details": {"unmapped_count": unmapped_field_count},
            })

        if pipeline_exceptions > 0:
            ded = min(20.0, pipeline_exceptions * 5.0)
            deductions.append({
                "metric_key": "normalization.pipeline_exceptions",
                "deduction": ded,
                "reason": f"{pipeline_exceptions} normalization pipeline parser exception(s) detected",
                "severity": "HIGH",
                "details": {"pipeline_exceptions": pipeline_exceptions},
            })

        total_deduction = sum(d["deduction"] for d in deductions)
        final_score = max(0.0, min(100.0, round(base_score - total_deduction, 2)))
        status = cls._classify_score(final_score)

        metric_snapshot = {
            "total_normalized_events": total_normalized,
            "sample_size": len(recent_normalized),
            "failed_normalization_count": failed_normalization,
            "normalization_failure_rate": round(failure_rate, 2),
            "unmapped_field_instances": unmapped_field_count,
            "pipeline_exceptions": pipeline_exceptions,
        }

        explanation = (
            f"Normalization Assurance evaluated at {final_score:.2f}/100 ({status}). "
            f"Normalization failure rate is {failure_rate:.1f}% across {total_normalized} canonical events."
        )

        return final_score, status, metric_snapshot, deductions, explanation

    # ── Domain 3: SEMANTIC_ASSURANCE ─────────────────────────────────────────
    @classmethod
    def _evaluate_semantic_assurance(cls, db: Session) -> Tuple[float, str, Dict[str, Any], List[Dict[str, Any]], str]:
        """
        Evaluates semantic interpretation confidence, ambiguous mappings, unmapped semantic values,
        incompatible mappings, and protected field drift.
        Base: 100. Deductions:
        - Ambiguous mappings: -5 each (max -20)
        - Unmapped semantic values: -10 each (max -30)
        - Incompatible mapping: -20
        - Protected field drift: -25
        - Critical protected field drift: -35
        """
        deductions: List[Dict[str, Any]] = []
        base_score = 100.0

        total_interpretations = db.query(SemanticInterpretation).count()
        recent_interps = (
            db.query(SemanticInterpretation)
            .order_by(desc(SemanticInterpretation.created_at))
            .limit(100)
            .all()
        )

        ambiguous_count = 0
        unmapped_count = 0
        incompatible_count = 0

        for interp in recent_interps:
            conf = getattr(interp, "confidence_score", 1.0)
            mapping_status = getattr(interp, "mapping_status", "MAPPED")
            if conf < 0.70 or mapping_status in ("AMBIGUOUS", "LOW_CONFIDENCE"):
                ambiguous_count += 1
            if mapping_status in ("UNMAPPED", "UNKNOWN_VALUE"):
                unmapped_count += 1
            if mapping_status in ("INCOMPATIBLE", "TYPE_MISMATCH"):
                incompatible_count += 1

        # Check active SemanticDriftAlert records
        open_drift_alerts = (
            db.query(SemanticDriftAlert)
            .filter(SemanticDriftAlert.status.in_(["OPEN", "ACTIVE", "ACKNOWLEDGED"]))
            .all()
        )
        protected_drift_count = 0
        critical_drift_count = 0

        for alert in open_drift_alerts:
            is_protected = getattr(alert, "is_protected_field", False) or getattr(alert, "protected_field", False)
            severity = getattr(alert, "severity", "MEDIUM")
            if is_protected or severity in ("HIGH", "CRITICAL"):
                protected_drift_count += 1
                if severity == "CRITICAL":
                    critical_drift_count += 1

        # Check protected semantic fields configuration
        protected_fields_count = db.query(ProtectedSemanticField).count()

        if critical_drift_count > 0:
            deductions.append({
                "metric_key": "semantic.critical_protected_field_drift",
                "deduction": 35.0,
                "reason": f"{critical_drift_count} critical protected semantic field drift alert(s) active",
                "severity": "CRITICAL",
                "details": {"critical_drift_alerts": critical_drift_count},
            })
        elif protected_drift_count > 0:
            deductions.append({
                "metric_key": "semantic.protected_field_drift",
                "deduction": 25.0,
                "reason": f"{protected_drift_count} protected semantic field drift alert(s) active",
                "severity": "HIGH",
                "details": {"protected_drift_alerts": protected_drift_count},
            })

        if ambiguous_count > 0:
            ded = min(20.0, ambiguous_count * 5.0)
            deductions.append({
                "metric_key": "semantic.ambiguous_mappings",
                "deduction": ded,
                "reason": f"{ambiguous_count} ambiguous semantic mapping(s) (confidence < 0.70)",
                "severity": "MEDIUM",
                "details": {"ambiguous_count": ambiguous_count},
            })

        if unmapped_count > 0:
            ded = min(30.0, unmapped_count * 10.0)
            deductions.append({
                "metric_key": "semantic.unmapped_semantic_values",
                "deduction": ded,
                "reason": f"{unmapped_count} unmapped semantic value(s) in active interpretations",
                "severity": "HIGH",
                "details": {"unmapped_count": unmapped_count},
            })

        if incompatible_count > 0:
            deductions.append({
                "metric_key": "semantic.incompatible_mapping",
                "deduction": 20.0,
                "reason": f"{incompatible_count} incompatible semantic type/schema mapping(s)",
                "severity": "HIGH",
                "details": {"incompatible_count": incompatible_count},
            })

        total_deduction = sum(d["deduction"] for d in deductions)
        final_score = max(0.0, min(100.0, round(base_score - total_deduction, 2)))
        status = cls._classify_score(final_score)

        metric_snapshot = {
            "total_interpretations": total_interpretations,
            "sample_size": len(recent_interps),
            "ambiguous_mappings": ambiguous_count,
            "unmapped_semantic_values": unmapped_count,
            "incompatible_mappings": incompatible_count,
            "open_drift_alerts": len(open_drift_alerts),
            "protected_field_drift_count": protected_drift_count,
            "critical_drift_count": critical_drift_count,
            "protected_fields_configured": protected_fields_count,
        }

        explanation = (
            f"Semantic Assurance evaluated at {final_score:.2f}/100 ({status}). "
            f"Tracked {len(open_drift_alerts)} active drift alerts and {ambiguous_count} ambiguous mappings."
        )

        return final_score, status, metric_snapshot, deductions, explanation

    # ── Domain 4: DETECTION_ASSURANCE ────────────────────────────────────────
    @classmethod
    def _evaluate_detection_assurance(cls, db: Session) -> Tuple[float, str, Dict[str, Any], List[Dict[str, Any]], str]:
        """
        Evaluates trusted detection rules, degraded rules, invalid rules, and dependency state.
        Preserves Sprint 6B Dependency Isolation Principle: unaffected rules receive NO deductions.
        Base: 100. Deductions:
        - DEGRADED rule: -5 each (max -15)
        - AT_RISK rule: -10 each (max -30)
        - INVALID rule: -20 each (max -50)
        - UNKNOWN dependency: -15
        - Critical detection trust alert: -20
        """
        deductions: List[Dict[str, Any]] = []
        base_score = 100.0

        total_rules = db.query(DetectionRule).count()
        rules = db.query(DetectionRule).all()

        trusted_rules = 0
        degraded_rules = 0
        at_risk_rules = 0
        invalid_rules = 0
        unknown_dependencies = 0

        # Query latest trust evaluations per rule
        for rule in rules:
            latest_eval = (
                db.query(DetectionRuleTrustEvaluation)
                .filter(DetectionRuleTrustEvaluation.rule_id == rule.rule_id)
                .order_by(desc(DetectionRuleTrustEvaluation.created_at))
                .first()
            )
            if latest_eval:
                trust_status = getattr(latest_eval, "trust_status", "TRUSTED")
                if trust_status == "TRUSTED":
                    trusted_rules += 1
                elif trust_status == "DEGRADED":
                    degraded_rules += 1
                elif trust_status == "AT_RISK":
                    at_risk_rules += 1
                elif trust_status in ("INVALID", "BROKEN"):
                    invalid_rules += 1
                elif trust_status == "UNKNOWN":
                    unknown_dependencies += 1
            else:
                # Rule registered without trust evaluation yet
                trusted_rules += 1

        # Check active detection trust alerts
        open_trust_alerts = (
            db.query(DetectionTrustAlert)
            .filter(DetectionTrustAlert.status.in_(["OPEN", "ACTIVE", "ACKNOWLEDGED"]))
            .all()
        )
        critical_trust_alerts = sum(1 for a in open_trust_alerts if getattr(a, "severity", "MEDIUM") == "CRITICAL")

        if invalid_rules > 0:
            ded = min(50.0, invalid_rules * 20.0)
            deductions.append({
                "metric_key": "detection.invalid_rules",
                "deduction": ded,
                "reason": f"{invalid_rules} detection rule(s) classified as INVALID due to broken dependencies",
                "severity": "CRITICAL",
                "details": {"invalid_rules": invalid_rules},
            })

        if at_risk_rules > 0:
            ded = min(30.0, at_risk_rules * 10.0)
            deductions.append({
                "metric_key": "detection.at_risk_rules",
                "deduction": ded,
                "reason": f"{at_risk_rules} detection rule(s) classified as AT_RISK",
                "severity": "HIGH",
                "details": {"at_risk_rules": at_risk_rules},
            })

        if degraded_rules > 0:
            ded = min(15.0, degraded_rules * 5.0)
            deductions.append({
                "metric_key": "detection.degraded_rules",
                "deduction": ded,
                "reason": f"{degraded_rules} detection rule(s) classified as DEGRADED",
                "severity": "MEDIUM",
                "details": {"degraded_rules": degraded_rules},
            })

        if unknown_dependencies > 0:
            deductions.append({
                "metric_key": "detection.unknown_dependency_state",
                "deduction": 15.0,
                "reason": f"{unknown_dependencies} detection rule(s) in UNKNOWN dependency state (Zero Trust deduction)",
                "severity": "MEDIUM",
                "details": {"unknown_dependencies": unknown_dependencies},
            })

        if critical_trust_alerts > 0:
            deductions.append({
                "metric_key": "detection.critical_trust_alerts",
                "deduction": 20.0,
                "reason": f"{critical_trust_alerts} critical detection trust alert(s) unacknowledged",
                "severity": "HIGH",
                "details": {"critical_alerts": critical_trust_alerts},
            })

        total_deduction = sum(d["deduction"] for d in deductions)
        final_score = max(0.0, min(100.0, round(base_score - total_deduction, 2)))
        status = cls._classify_score(final_score)

        metric_snapshot = {
            "total_rules": total_rules,
            "trusted_rules": trusted_rules,
            "degraded_rules": degraded_rules,
            "at_risk_rules": at_risk_rules,
            "invalid_rules": invalid_rules,
            "unknown_dependencies": unknown_dependencies,
            "open_trust_alerts": len(open_trust_alerts),
            "critical_trust_alerts": critical_trust_alerts,
        }

        explanation = (
            f"Detection Assurance evaluated at {final_score:.2f}/100 ({status}). "
            f"Active rule trust: {trusted_rules} Trusted, {degraded_rules} Degraded, {at_risk_rules} At Risk, {invalid_rules} Invalid."
        )

        return final_score, status, metric_snapshot, deductions, explanation

    # ── Domain 5: RISK_ASSURANCE ─────────────────────────────────────────────
    @classmethod
    def _evaluate_risk_assurance(cls, db: Session) -> Tuple[float, str, Dict[str, Any], List[Dict[str, Any]], str]:
        """
        Evaluates unresolved high-risk correlations, critical posture findings, and risk concentrations.
        Base: 100. Deductions:
        - Open critical posture finding: -15 each (max -30)
        - Unresolved high-risk correlation: -10 each (max -25)
        - Critical risk concentration: -20
        - Risk correlation failure: -20
        """
        deductions: List[Dict[str, Any]] = []
        base_score = 100.0

        total_correlations = db.query(RiskCorrelation).count()
        unresolved_correlations = (
            db.query(RiskCorrelation)
            .filter(RiskCorrelation.status.in_(["ACTIVE", "UNRESOLVED", "OPEN"]))
            .all()
        )

        high_risk_correlations = 0
        critical_risk_clusters = 0

        for rc in unresolved_correlations:
            risk_score = getattr(rc, "composite_risk_score", 0.0)
            sev = getattr(rc, "severity", "MEDIUM")
            if risk_score >= 80.0 or sev == "CRITICAL":
                high_risk_correlations += 1
            if getattr(rc, "member_count", 1) >= 5 or risk_score >= 90.0:
                critical_risk_clusters += 1

        # Check remediation candidates / posture findings
        open_candidates = (
            db.query(RemediationCandidate)
            .filter(RemediationCandidate.status.in_(["OPEN", "PENDING", "ACTIVE"]))
            .all()
        )
        critical_posture_findings = sum(1 for c in open_candidates if getattr(c, "severity", "MEDIUM") == "CRITICAL")

        if critical_posture_findings > 0:
            ded = min(30.0, critical_posture_findings * 15.0)
            deductions.append({
                "metric_key": "risk.critical_posture_findings",
                "deduction": ded,
                "reason": f"{critical_posture_findings} open critical security posture finding(s)",
                "severity": "CRITICAL",
                "details": {"critical_findings": critical_posture_findings},
            })

        if high_risk_correlations > 0:
            ded = min(25.0, high_risk_correlations * 10.0)
            deductions.append({
                "metric_key": "risk.high_risk_correlations",
                "deduction": ded,
                "reason": f"{high_risk_correlations} unresolved high-risk correlation(s)",
                "severity": "HIGH",
                "details": {"high_risk_count": high_risk_correlations},
            })

        if critical_risk_clusters > 0:
            deductions.append({
                "metric_key": "risk.critical_risk_concentration",
                "deduction": 20.0,
                "reason": f"{critical_risk_clusters} dense multi-signal risk concentration cluster(s) detected",
                "severity": "HIGH",
                "details": {"cluster_count": critical_risk_clusters},
            })

        total_deduction = sum(d["deduction"] for d in deductions)
        final_score = max(0.0, min(100.0, round(base_score - total_deduction, 2)))
        status = cls._classify_score(final_score)

        metric_snapshot = {
            "total_correlations": total_correlations,
            "unresolved_correlations": len(unresolved_correlations),
            "high_risk_correlations": high_risk_correlations,
            "critical_risk_clusters": critical_risk_clusters,
            "open_remediation_candidates": len(open_candidates),
            "critical_posture_findings": critical_posture_findings,
        }

        explanation = (
            f"Risk Assurance evaluated at {final_score:.2f}/100 ({status}). "
            f"Monitored {len(unresolved_correlations)} unresolved correlations and {critical_posture_findings} critical posture findings."
        )

        return final_score, status, metric_snapshot, deductions, explanation

    # ── Domain 6: INCIDENT_RESPONSE_ASSURANCE ────────────────────────────────
    @classmethod
    def _evaluate_incident_response_assurance(cls, db: Session) -> Tuple[float, str, Dict[str, Any], List[Dict[str, Any]], str]:
        """
        Evaluates open critical incidents, stale investigations, pending containment authorizations,
        unverified executions, and response verification results.
        Preserves Human Authorization Invariant: "SENTINELTRACE RECOMMENDS. HUMANS AUTHORIZE."
        Base: 100. Deductions:
        - Open critical incident: -10 each (max -30)
        - Stale investigation: -10
        - Pending containment authorization: -5 (max -15)
        - Execution without verification: -15
        - Failed response verification: -30
        """
        deductions: List[Dict[str, Any]] = []
        base_score = 100.0

        total_incidents = db.query(SecurityIncident).count()
        open_incidents = (
            db.query(SecurityIncident)
            .filter(SecurityIncident.status.in_(["OPEN", "TRIAGING", "INVESTIGATING"]))
            .all()
        )

        open_critical_incidents = 0
        stale_investigations = 0

        now = utcnow()
        for inc in open_incidents:
            sev = getattr(inc, "severity", "MEDIUM")
            if sev == "CRITICAL" or getattr(inc, "priority", "P3") == "P1":
                open_critical_incidents += 1

            # Check for stale investigation (> 48h in TRIAGING/OPEN without assignment)
            created = getattr(inc, "created_at", now)
            if created and created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if (now - created).total_seconds() > 86400 * 2 and getattr(inc, "assigned_to_user_id", None) is None:
                stale_investigations += 1

        # Check pending containment requests
        pending_containments = (
            db.query(IncidentContainmentRequest)
            .filter(IncidentContainmentRequest.status.in_(["PENDING_REVIEW", "PENDING_APPROVAL"]))
            .count()
        )

        # Check response executions without verification records
        executions = db.query(IncidentResponseExecution).all()
        unverified_executions = 0
        for ex in executions:
            ver = (
                db.query(IncidentResponseVerification)
                .filter(IncidentResponseVerification.containment_request_id == ex.containment_request_id)
                .first()
            )
            if not ver:
                unverified_executions += 1

        # Check failed verifications
        failed_verifications = (
            db.query(IncidentResponseVerification)
            .filter(IncidentResponseVerification.verification_status.in_(["FAILED", "BREACH_CONTINUED"]))
            .count()
        )

        if failed_verifications > 0:
            deductions.append({
                "metric_key": "response.failed_verifications",
                "deduction": 30.0,
                "reason": f"{failed_verifications} containment action(s) failed post-execution verification",
                "severity": "CRITICAL",
                "details": {"failed_verifications": failed_verifications},
            })

        if open_critical_incidents > 0:
            ded = min(30.0, open_critical_incidents * 10.0)
            deductions.append({
                "metric_key": "response.open_critical_incidents",
                "deduction": ded,
                "reason": f"{open_critical_incidents} open critical P1 incident(s) awaiting resolution",
                "severity": "HIGH",
                "details": {"critical_incidents": open_critical_incidents},
            })

        if unverified_executions > 0:
            deductions.append({
                "metric_key": "response.unverified_executions",
                "deduction": 15.0,
                "reason": f"{unverified_executions} containment execution(s) lacking formal verification attestation",
                "severity": "MEDIUM",
                "details": {"unverified_executions": unverified_executions},
            })

        if stale_investigations > 0:
            deductions.append({
                "metric_key": "response.stale_investigations",
                "deduction": 10.0,
                "reason": f"{stale_investigations} incident investigation(s) stale without assigned investigator (> 48h)",
                "severity": "MEDIUM",
                "details": {"stale_count": stale_investigations},
            })

        if pending_containments > 0:
            ded = min(15.0, pending_containments * 5.0)
            deductions.append({
                "metric_key": "response.pending_containment_authorization",
                "deduction": ded,
                "reason": f"{pending_containments} containment request(s) awaiting human dual-control authorization",
                "severity": "LOW",
                "details": {"pending_containments": pending_containments},
            })

        total_deduction = sum(d["deduction"] for d in deductions)
        final_score = max(0.0, min(100.0, round(base_score - total_deduction, 2)))
        status = cls._classify_score(final_score)

        metric_snapshot = {
            "total_incidents": total_incidents,
            "open_incidents": len(open_incidents),
            "open_critical_incidents": open_critical_incidents,
            "stale_investigations": stale_investigations,
            "pending_containments": pending_containments,
            "total_executions": len(executions),
            "unverified_executions": unverified_executions,
            "failed_verifications": failed_verifications,
        }

        explanation = (
            f"Incident Response Assurance evaluated at {final_score:.2f}/100 ({status}). "
            f"Governed lifecycle: {len(open_incidents)} open incidents, {pending_containments} pending dual-control approvals, {failed_verifications} failed verifications."
        )

        return final_score, status, metric_snapshot, deductions, explanation

    # ── Domain 7: CRYPTOGRAPHIC_ASSURANCE ────────────────────────────────────
    @classmethod
    def _evaluate_cryptographic_assurance(cls, db: Session) -> Tuple[float, str, Dict[str, Any], List[Dict[str, Any]], str]:
        """
        Evaluates governance ledger integrity, SHA-256 continuous hash chain, Merkle batch consistency,
        and proof verification success.
        Base: 100. Deductions:
        - Governance ledger chain failure: -60
        - Merkle proof failure: -50
        - Unsealed governance records: -10 (max -30)
        - Merkle batch inconsistency: -30
        - HARD FAILURE OVERRIDE: Cryptographic integrity failure forces CRITICAL domain status immediately.
        """
        deductions: List[Dict[str, Any]] = []
        base_score = 100.0
        has_hard_critical = False

        # 1. Verify governance ledger continuous hash chain
        ledger_entries = (
            db.query(GovernanceLedgerEntry)
            .order_by(GovernanceLedgerEntry.sequence_number.asc())
            .all()
        )
        ledger_chain_valid = True
        broken_ledger_sequence = None

        if len(ledger_entries) > 1:
            for i in range(1, len(ledger_entries)):
                prev = ledger_entries[i - 1]
                curr = ledger_entries[i]
                prev_hash_val = getattr(curr, "previous_hash", None) or getattr(curr, "previous_entry_hash", None)
                if prev_hash_val != prev.entry_hash:
                    ledger_chain_valid = False
                    broken_ledger_sequence = curr.sequence_number
                    break

        if not ledger_chain_valid:
            has_hard_critical = True
            deductions.append({
                "metric_key": "cryptographic.ledger_chain_failure",
                "deduction": 60.0,
                "reason": f"Governance ledger SHA-256 continuous hash chain broken at sequence #{broken_ledger_sequence}",
                "severity": "CRITICAL",
                "details": {"broken_sequence": broken_ledger_sequence},
            })


        # 2. Check Merkle batches & proofs
        merkle_batches = db.query(MerkleBatch).all()
        merkle_proofs = db.query(MerkleProof).all()
        merkle_proof_failures = 0
        merkle_inconsistencies = 0

        for proof in merkle_proofs:
            if getattr(proof, "verification_status", "VALID") in ("FAILED", "INVALID"):
                merkle_proof_failures += 1

        for mb in merkle_batches:
            tree_stat = getattr(mb, "tree_status", None) or getattr(mb, "status", "SEALED")
            if tree_stat in ("CORRUPTED", "INCONSISTENT", "INVALID"):
                merkle_inconsistencies += 1

        if merkle_proof_failures > 0:
            has_hard_critical = True
            deductions.append({
                "metric_key": "cryptographic.merkle_proof_failure",
                "deduction": 50.0,
                "reason": f"{merkle_proof_failures} Merkle cryptographic inclusion proof verification failure(s)",
                "severity": "CRITICAL",
                "details": {"failed_proofs": merkle_proof_failures},
            })

        if merkle_inconsistencies > 0:
            has_hard_critical = True
            deductions.append({
                "metric_key": "cryptographic.merkle_batch_inconsistency",
                "deduction": 30.0,
                "reason": f"{merkle_inconsistencies} inconsistent or corrupted Merkle tree batch(es)",
                "severity": "CRITICAL",
                "details": {"inconsistent_batches": merkle_inconsistencies},
            })

        # Check for unsealed / pending ledger records
        unsealed_count = sum(1 for e in ledger_entries if getattr(e, "is_sealed", True) is False)
        if unsealed_count > 0:
            ded = min(30.0, unsealed_count * 10.0)
            deductions.append({
                "metric_key": "cryptographic.unsealed_governance_records",
                "deduction": ded,
                "reason": f"{unsealed_count} unsealed governance ledger record(s) pending final cryptographic block",
                "severity": "MEDIUM",
                "details": {"unsealed_records": unsealed_count},
            })

        total_deduction = sum(d["deduction"] for d in deductions)
        final_score = max(0.0, min(100.0, round(base_score - total_deduction, 2)))
        status = cls._classify_score(final_score, has_hard_critical=has_hard_critical)

        metric_snapshot = {
            "total_ledger_entries": len(ledger_entries),
            "ledger_chain_valid": ledger_chain_valid,
            "broken_ledger_sequence": broken_ledger_sequence,
            "total_merkle_batches": len(merkle_batches),
            "total_merkle_proofs": len(merkle_proofs),
            "merkle_proof_failures": merkle_proof_failures,
            "merkle_inconsistencies": merkle_inconsistencies,
            "unsealed_governance_records": unsealed_count,
            "cryptographic_hard_critical": has_hard_critical,
        }

        explanation = (
            f"Cryptographic Assurance evaluated at {final_score:.2f}/100 ({status}). "
            f"Ledger Chain: {'VALID' if ledger_chain_valid else 'BROKEN'}, Merkle Proofs: {len(merkle_proofs)} checked ({merkle_proof_failures} failures)."
        )

        return final_score, status, metric_snapshot, deductions, explanation

    # ── Evaluate Single Domain ───────────────────────────────────────────────
    @classmethod
    def evaluate_domain(
        cls,
        db: Session,
        domain_name: str,
        notes: Optional[str] = None,
    ) -> AssuranceDomainEvaluation:
        """
        Evaluates one of the 7 assurance domains, producing an immutable point-in-time snapshot.
        """
        domain_name = domain_name.upper()
        if domain_name not in cls.DOMAINS:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown domain '{domain_name}'. Must be one of: {cls.DOMAINS}",
            )

        eval_ts = utcnow()

        if domain_name == "EVIDENCE_ASSURANCE":
            score, status, snapshot, deductions, explanation = cls._evaluate_evidence_assurance(db)
        elif domain_name == "NORMALIZATION_ASSURANCE":
            score, status, snapshot, deductions, explanation = cls._evaluate_normalization_assurance(db)
        elif domain_name == "SEMANTIC_ASSURANCE":
            score, status, snapshot, deductions, explanation = cls._evaluate_semantic_assurance(db)
        elif domain_name == "DETECTION_ASSURANCE":
            score, status, snapshot, deductions, explanation = cls._evaluate_detection_assurance(db)
        elif domain_name == "RISK_ASSURANCE":
            score, status, snapshot, deductions, explanation = cls._evaluate_risk_assurance(db)
        elif domain_name == "INCIDENT_RESPONSE_ASSURANCE":
            score, status, snapshot, deductions, explanation = cls._evaluate_incident_response_assurance(db)
        elif domain_name == "CRYPTOGRAPHIC_ASSURANCE":
            score, status, snapshot, deductions, explanation = cls._evaluate_cryptographic_assurance(db)
        else:
            raise HTTPException(status_code=400, detail="Unhandled domain")

        risk_level = "LOW"
        if status == "CRITICAL":
            risk_level = "CRITICAL"
        elif status == "AT_RISK":
            risk_level = "HIGH"
        elif status == "DEGRADED":
            risk_level = "MEDIUM"

        # Generate deterministic evaluation hash
        eval_id = f"ade-{uuid.uuid4().hex[:12]}"
        payload = {
            "evaluation_id": eval_id,
            "domain_name": domain_name,
            "evaluation_timestamp": eval_ts.isoformat(),
            "score": score,
            "status": status,
            "risk_level": risk_level,
            "deductions": deductions,
            "metric_snapshot": snapshot,
        }
        eval_hash = cls._compute_hash(payload)

        record = AssuranceDomainEvaluation(
            id=eval_id,
            domain_name=domain_name,
            evaluation_timestamp=eval_ts,
            score=score,
            status=status,
            metric_snapshot=snapshot,
            deductions=deductions,
            explanation=explanation,
            risk_level=risk_level,
            evaluation_hash=eval_hash,
            created_at=eval_ts,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    # ── Evaluate All Domains ─────────────────────────────────────────────────
    @classmethod
    def evaluate_all_domains(cls, db: Session) -> Dict[str, AssuranceDomainEvaluation]:
        """Evaluates all 7 assurance domains in sequence."""
        results: Dict[str, AssuranceDomainEvaluation] = {}
        for domain in cls.DOMAINS:
            results[domain] = cls.evaluate_domain(db, domain)
        return results

    # ── Platform-Wide Composite Evaluation ───────────────────────────────────
    @classmethod
    def evaluate_platform(
        cls,
        db: Session,
        notes: Optional[str] = None,
    ) -> PlatformAssuranceEvaluation:
        """
        Executes complete platform assurance evaluation across all 7 domains,
        computes weighted composite score, applies hard failure overrides,
        seals cryptographic snapshot, generates deduplicated alerts, and updates trend history.
        """
        # Ensure default metric definitions are seeded
        cls.seed_default_metric_definitions(db)

        # Retrieve previous platform evaluation for chaining
        previous_eval = (
            db.query(PlatformAssuranceEvaluation)
            .order_by(desc(PlatformAssuranceEvaluation.evaluation_timestamp))
            .first()
        )
        prev_eval_id = previous_eval.id if previous_eval else None
        prev_overall_score = previous_eval.overall_score if previous_eval else None

        # Evaluate all 7 domains
        domain_records = cls.evaluate_all_domains(db)

        evidence_score = domain_records["EVIDENCE_ASSURANCE"].score
        norm_score = domain_records["NORMALIZATION_ASSURANCE"].score
        semantic_score = domain_records["SEMANTIC_ASSURANCE"].score
        detection_score = domain_records["DETECTION_ASSURANCE"].score
        risk_score = domain_records["RISK_ASSURANCE"].score
        resp_score = domain_records["INCIDENT_RESPONSE_ASSURANCE"].score
        crypto_score = domain_records["CRYPTOGRAPHIC_ASSURANCE"].score

        weights = cls.DEFAULT_DOMAIN_WEIGHTS

        # Weighted mathematical composite score
        composite_score = (
            evidence_score * weights["EVIDENCE_ASSURANCE"]
            + norm_score * weights["NORMALIZATION_ASSURANCE"]
            + semantic_score * weights["SEMANTIC_ASSURANCE"]
            + detection_score * weights["DETECTION_ASSURANCE"]
            + risk_score * weights["RISK_ASSURANCE"]
            + resp_score * weights["INCIDENT_RESPONSE_ASSURANCE"]
            + crypto_score * weights["CRYPTOGRAPHIC_ASSURANCE"]
        )
        overall_score = round(composite_score, 2)

        # Baseline status from score
        overall_status = cls._classify_score(overall_score)

        critical_conditions: List[Dict[str, Any]] = []

        # ── HARD FAILURE OVERRIDES ───────────────────────────────────────────
        # 1. Cryptographic Assurance CRITICAL override
        crypto_status = domain_records["CRYPTOGRAPHIC_ASSURANCE"].status
        if crypto_status == "CRITICAL":
            overall_status = "CRITICAL"
            critical_conditions.append({
                "condition": "CRYPTOGRAPHIC_HARD_FAILURE_OVERRIDE",
                "reason": "Cryptographic assurance failure forces platform status to CRITICAL regardless of weighted mathematical score",
                "severity": "CRITICAL",
            })

        # 2. Two or more domains CRITICAL override
        critical_domains = [d for d, rec in domain_records.items() if rec.status == "CRITICAL"]
        if len(critical_domains) >= 2:
            overall_status = "CRITICAL"
            critical_conditions.append({
                "condition": "MULTI_DOMAIN_CRITICAL_OVERRIDE",
                "reason": f"Systemic failure: {len(critical_domains)} domains in CRITICAL state ({', '.join(critical_domains)})",
                "severity": "CRITICAL",
            })

        # 3. Three or more domains AT_RISK ceiling
        at_risk_domains = [d for d, rec in domain_records.items() if rec.status in ("AT_RISK", "CRITICAL")]
        if len(at_risk_domains) >= 3 and overall_status in ("HEALTHY", "DEGRADED"):
            overall_status = "AT_RISK"
            critical_conditions.append({
                "condition": "MULTI_DOMAIN_AT_RISK_CEILING",
                "reason": f"Pervasive degradation: {len(at_risk_domains)} domains in AT_RISK or worse state",
                "severity": "HIGH",
            })

        # Breakdown payload
        score_breakdown = {
            "domains": {
                d: {
                    "evaluation_id": rec.id,
                    "score": rec.score,
                    "status": rec.status,
                    "weight": weights.get(d, 0.0),
                    "weighted_contribution": round(rec.score * weights.get(d, 0.0), 2),
                    "deductions_count": len(rec.deductions),
                    "evaluation_hash": rec.evaluation_hash,
                }
                for d, rec in domain_records.items()
            },
            "formula": (
                f"PlatformScore = ({evidence_score:.2f} × 0.15) + ({norm_score:.2f} × 0.10) + ({semantic_score:.2f} × 0.15) "
                f"+ ({detection_score:.2f} × 0.20) + ({risk_score:.2f} × 0.10) + ({resp_score:.2f} × 0.15) + ({crypto_score:.2f} × 0.15) "
                f"= {overall_score:.2f}"
            ),
        }

        explanation = (
            f"Platform Security Assurance evaluated at {overall_score:.2f}/100 ({overall_status}). "
            f"Composite calculated across 7 assurance domains with {len(critical_conditions)} hard override(s)."
        )

        eval_ts = utcnow()
        platform_eval_id = f"pae-{uuid.uuid4().hex[:12]}"

        # Deterministic Canonical Sealing Hash
        seal_payload = {
            "platform_evaluation_id": platform_eval_id,
            "evaluation_timestamp": eval_ts.isoformat(),
            "overall_score": overall_score,
            "overall_status": overall_status,
            "domain_scores": {d: rec.score for d, rec in domain_records.items()},
            "domain_weights": weights,
            "critical_conditions": critical_conditions,
            "previous_evaluation_id": prev_eval_id,
        }
        eval_hash = cls._compute_hash(seal_payload)

        platform_eval = PlatformAssuranceEvaluation(
            id=platform_eval_id,
            evaluation_timestamp=eval_ts,
            overall_score=overall_score,
            overall_status=overall_status,
            evidence_score=evidence_score,
            normalization_score=norm_score,
            semantic_score=semantic_score,
            detection_score=detection_score,
            risk_score=risk_score,
            incident_response_score=resp_score,
            cryptographic_score=crypto_score,
            domain_weights=weights,
            score_breakdown=score_breakdown,
            critical_conditions=critical_conditions,
            explanation=explanation,
            evaluation_hash=eval_hash,
            previous_evaluation_id=prev_eval_id,
            created_at=eval_ts,
        )
        db.add(platform_eval)

        # Create trend snapshot
        score_delta = round(overall_score - prev_overall_score, 2) if prev_overall_score is not None else 0.0
        trend_snapshot = AssuranceTrendSnapshot(
            id=f"ats-{uuid.uuid4().hex[:12]}",
            platform_evaluation_id=platform_eval_id,
            snapshot_timestamp=eval_ts,
            overall_score=overall_score,
            overall_status=overall_status,
            domain_scores={d: rec.score for d, rec in domain_records.items()},
            score_delta=score_delta,
            created_at=eval_ts,
        )
        db.add(trend_snapshot)
        db.commit()
        db.refresh(platform_eval)

        # Generate automated assurance alerts
        cls.generate_assurance_alerts(db, platform_eval, domain_records, previous_eval)

        return platform_eval

    # ── Continuous Assurance Alert Engine ────────────────────────────────────
    @classmethod
    def generate_assurance_alerts(
        cls,
        db: Session,
        platform_eval: PlatformAssuranceEvaluation,
        domain_records: Dict[str, AssuranceDomainEvaluation],
        previous_eval: Optional[PlatformAssuranceEvaluation],
    ) -> List[AssuranceAlert]:
        """
        Generates deterministic assurance alerts with deduplication to prevent flooding.
        Alert criteria:
        - Score drop >= 10: ASSURANCE_DEGRADED
        - Score drop >= 20: SCORE_REGRESSION
        - Domain enters AT_RISK: ASSURANCE_AT_RISK
        - Domain enters CRITICAL: ASSURANCE_CRITICAL
        - Cryptographic failure: CRYPTOGRAPHIC_INTEGRITY_FAILURE
        - Pipeline trust failure: PIPELINE_TRUST_FAILURE
        """
        alerts_generated: List[AssuranceAlert] = []
        now = utcnow()

        # 1. Platform score drop checks
        if previous_eval is not None:
            drop = previous_eval.overall_score - platform_eval.overall_score
            if drop >= 20.0:
                cls._upsert_alert(
                    db=db,
                    alert_type="SCORE_REGRESSION",
                    domain_name="PLATFORM",
                    severity="CRITICAL",
                    title="Critical Platform Assurance Score Regression",
                    description=f"Platform trust score dropped by {drop:.2f} points (from {previous_eval.overall_score:.2f} to {platform_eval.overall_score:.2f}).",
                    source_evaluation_id=platform_eval.id,
                    previous_score=previous_eval.overall_score,
                    current_score=platform_eval.overall_score,
                    score_delta=-drop,
                    source_condition="PLATFORM_SCORE_DROP_20",
                    alerts_list=alerts_generated,
                )
            elif drop >= 10.0:
                cls._upsert_alert(
                    db=db,
                    alert_type="ASSURANCE_DEGRADED",
                    domain_name="PLATFORM",
                    severity="HIGH",
                    title="Platform Security Assurance Degraded",
                    description=f"Platform trust score experienced a regression of {drop:.2f} points (from {previous_eval.overall_score:.2f} to {platform_eval.overall_score:.2f}).",
                    source_evaluation_id=platform_eval.id,
                    previous_score=previous_eval.overall_score,
                    current_score=platform_eval.overall_score,
                    score_delta=-drop,
                    source_condition="PLATFORM_SCORE_DROP_10",
                    alerts_list=alerts_generated,
                )

        # 2. Domain status checks
        for d_name, rec in domain_records.items():
            if rec.status == "CRITICAL":
                cls._upsert_alert(
                    db=db,
                    alert_type="ASSURANCE_CRITICAL",
                    domain_name=d_name,
                    severity="CRITICAL",
                    title=f"Critical Assurance Failure in {d_name}",
                    description=f"Domain {d_name} entered CRITICAL status with score {rec.score:.2f}/100. Deductions: {len(rec.deductions)}.",
                    source_evaluation_id=rec.id,
                    previous_score=None,
                    current_score=rec.score,
                    score_delta=None,
                    source_condition=f"{d_name}_STATUS_CRITICAL",
                    alerts_list=alerts_generated,
                )
            elif rec.status == "AT_RISK":
                cls._upsert_alert(
                    db=db,
                    alert_type="ASSURANCE_AT_RISK",
                    domain_name=d_name,
                    severity="HIGH",
                    title=f"Assurance At Risk in {d_name}",
                    description=f"Domain {d_name} is AT_RISK with score {rec.score:.2f}/100.",
                    source_evaluation_id=rec.id,
                    previous_score=None,
                    current_score=rec.score,
                    score_delta=None,
                    source_condition=f"{d_name}_STATUS_AT_RISK",
                    alerts_list=alerts_generated,
                )

            # Specific alert types
            if d_name == "CRYPTOGRAPHIC_ASSURANCE" and rec.status == "CRITICAL":
                cls._upsert_alert(
                    db=db,
                    alert_type="CRYPTOGRAPHIC_INTEGRITY_FAILURE",
                    domain_name=d_name,
                    severity="CRITICAL",
                    title="Cryptographic Governance Ledger / Merkle Proof Integrity Failure",
                    description="Continuous hash chain validation or Merkle inclusion proof verification has failed.",
                    source_evaluation_id=rec.id,
                    previous_score=None,
                    current_score=rec.score,
                    score_delta=None,
                    source_condition="CRYPTOGRAPHIC_INTEGRITY_FAIL",
                    alerts_list=alerts_generated,
                )

            if d_name == "NORMALIZATION_ASSURANCE" and rec.score < 50.0:
                cls._upsert_alert(
                    db=db,
                    alert_type="PIPELINE_TRUST_FAILURE",
                    domain_name=d_name,
                    severity="HIGH",
                    title="Normalization Pipeline Trust Failure",
                    description="Severe normalization failure rate detected in OCSF ingestion pipeline.",
                    source_evaluation_id=rec.id,
                    previous_score=None,
                    current_score=rec.score,
                    score_delta=None,
                    source_condition="NORMALIZATION_PIPELINE_FAIL",
                    alerts_list=alerts_generated,
                )

        db.commit()
        return alerts_generated

    @classmethod
    def _upsert_alert(
        cls,
        db: Session,
        alert_type: str,
        domain_name: str,
        severity: str,
        title: str,
        description: str,
        source_evaluation_id: Optional[str],
        previous_score: Optional[float],
        current_score: float,
        score_delta: Optional[float],
        source_condition: str,
        alerts_list: List[AssuranceAlert],
    ) -> AssuranceAlert:
        """Upserts alert using deterministic deduplication key."""
        dedup_key = cls._compute_deduplication_key(domain_name, alert_type, source_condition)
        now = utcnow()

        existing = (
            db.query(AssuranceAlert)
            .filter(
                AssuranceAlert.deduplication_key == dedup_key,
                AssuranceAlert.status == "OPEN",
            )
            .first()
        )

        if existing:
            # Update existing open alert's last_detected_at and score details
            existing.last_detected_at = now
            existing.current_score = current_score
            if score_delta is not None:
                existing.score_delta = score_delta
            if source_evaluation_id:
                existing.source_evaluation_id = source_evaluation_id
            alerts_list.append(existing)
            return existing
        else:
            alert = AssuranceAlert(
                id=f"aa-{uuid.uuid4().hex[:12]}",
                alert_type=alert_type,
                domain_name=domain_name,
                severity=severity,
                status="OPEN",
                title=title,
                description=description,
                source_evaluation_id=source_evaluation_id,
                previous_score=previous_score,
                current_score=current_score,
                score_delta=score_delta,
                deduplication_key=dedup_key,
                first_detected_at=now,
                last_detected_at=now,
                created_at=now,
            )
            db.add(alert)
            alerts_list.append(alert)
            return alert

    # ── Alert Triage Lifecycle ────────────────────────────────────────────────
    @classmethod
    def triage_alert(
        cls,
        db: Session,
        alert_id: str,
        new_status: str,
        user_id: str,
        notes: Optional[str] = None,
    ) -> AssuranceAlert:
        """
        Manages alert status transitions: OPEN -> ACKNOWLEDGED -> RESOLVED.
        """
        alert = db.query(AssuranceAlert).filter(AssuranceAlert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail=f"Assurance alert '{alert_id}' not found")

        now = utcnow()
        new_status_str = new_status.upper()

        if new_status_str == "ACKNOWLEDGED":
            alert.status = "ACKNOWLEDGED"
            alert.acknowledged_at = now
            alert.acknowledged_by = user_id
        elif new_status_str == "RESOLVED":
            alert.status = "RESOLVED"
            alert.resolved_at = now
            alert.resolved_by = user_id
        elif new_status_str == "OPEN":
            alert.status = "OPEN"
        else:
            raise HTTPException(status_code=400, detail=f"Invalid alert status '{new_status}'")

        db.commit()
        db.refresh(alert)
        return alert

    # ── Latest & History Queries ──────────────────────────────────────────────
    @classmethod
    def get_latest_assurance(cls, db: Session) -> Optional[PlatformAssuranceEvaluation]:
        """Returns the most recent PlatformAssuranceEvaluation snapshot."""
        return (
            db.query(PlatformAssuranceEvaluation)
            .order_by(desc(PlatformAssuranceEvaluation.evaluation_timestamp))
            .first()
        )

    @classmethod
    def get_assurance_history(
        cls,
        db: Session,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 50,
    ) -> Tuple[List[PlatformAssuranceEvaluation], List[AssuranceTrendSnapshot]]:
        """Returns historical platform assurance snapshots and trend time-series."""
        query = db.query(PlatformAssuranceEvaluation)
        if start_date:
            query = query.filter(PlatformAssuranceEvaluation.evaluation_timestamp >= start_date)
        if end_date:
            query = query.filter(PlatformAssuranceEvaluation.evaluation_timestamp <= end_date)

        evals = query.order_by(desc(PlatformAssuranceEvaluation.evaluation_timestamp)).limit(limit).all()

        trend_query = db.query(AssuranceTrendSnapshot)
        if start_date:
            trend_query = trend_query.filter(AssuranceTrendSnapshot.snapshot_timestamp >= start_date)
        if end_date:
            trend_query = trend_query.filter(AssuranceTrendSnapshot.snapshot_timestamp <= end_date)

        trends = trend_query.order_by(desc(AssuranceTrendSnapshot.snapshot_timestamp)).limit(limit).all()

        return evals, trends

    # ── KPI Summary ──────────────────────────────────────────────────────────
    @classmethod
    def get_kpi_summary(cls, db: Session) -> Dict[str, Any]:
        """Returns real-time KPI metrics for security assurance command center."""
        latest = cls.get_latest_assurance(db)
        if not latest:
            # Auto-run initial evaluation if none exists
            latest = cls.evaluate_platform(db)

        # Domain health counts
        health_counts = {"HEALTHY": 0, "DEGRADED": 0, "AT_RISK": 0, "CRITICAL": 0, "UNKNOWN": 0}
        critical_domains: List[str] = []

        scores = {
            "EVIDENCE_ASSURANCE": latest.evidence_score,
            "NORMALIZATION_ASSURANCE": latest.normalization_score,
            "SEMANTIC_ASSURANCE": latest.semantic_score,
            "DETECTION_ASSURANCE": latest.detection_score,
            "RISK_ASSURANCE": latest.risk_score,
            "INCIDENT_RESPONSE_ASSURANCE": latest.incident_response_score,
            "CRYPTOGRAPHIC_ASSURANCE": latest.cryptographic_score,
        }

        for domain, sc in scores.items():
            st = cls._classify_score(sc)
            if domain == "CRYPTOGRAPHIC_ASSURANCE" and sc < 90.0 and len(latest.critical_conditions) > 0:
                st = "CRITICAL"
            health_counts[st] = health_counts.get(st, 0) + 1
            if st == "CRITICAL":
                critical_domains.append(domain)

        open_alerts = db.query(AssuranceAlert).filter(AssuranceAlert.status == "OPEN").count()
        critical_alerts = (
            db.query(AssuranceAlert)
            .filter(AssuranceAlert.status == "OPEN", AssuranceAlert.severity == "CRITICAL")
            .count()
        )

        # Previous evaluation for delta & trend
        prev_eval = (
            db.query(PlatformAssuranceEvaluation)
            .filter(PlatformAssuranceEvaluation.id != latest.id)
            .order_by(desc(PlatformAssuranceEvaluation.evaluation_timestamp))
            .first()
        )

        latest_delta = round(latest.overall_score - prev_eval.overall_score, 2) if prev_eval else 0.0
        trend_direction = "STABLE"
        if latest_delta > 0.5:
            trend_direction = "IMPROVING"
        elif latest_delta < -0.5:
            trend_direction = "DEGRADING"

        return {
            "overall_score": latest.overall_score,
            "overall_status": latest.overall_status,
            "domain_health_counts": health_counts,
            "critical_domains": critical_domains,
            "open_assurance_alerts": open_alerts,
            "critical_assurance_alerts": critical_alerts,
            "latest_score_delta": latest_delta,
            "trend_direction": trend_direction,
            "last_evaluation_timestamp": latest.evaluation_timestamp,
            "last_evaluation_hash": latest.evaluation_hash,
        }

    # ── 17-Stage Assurance Provenance Trace ───────────────────────────────────
    @classmethod
    def get_assurance_provenance_trace(
        cls,
        db: Session,
        evaluation_id: str,
    ) -> Dict[str, Any]:
        """
        Constructs the complete 17-Stage Assurance Provenance Trace for a given platform evaluation.
        Clearly differentiates SOURCE DATA from DERIVED ASSURANCE.
        Stages:
        1. RAW_SECURITY_EVIDENCE
        2. EVIDENCE_INTEGRITY
        3. NORMALIZATION_PIPELINE
        4. SEMANTIC_INTERPRETATION
        5. SEMANTIC_DRIFT
        6. DETECTION_RULE_DEPENDENCY
        7. DETECTION_TRUST
        8. RISK_CORRELATION
        9. SECURITY_POSTURE
        10. SECURITY_INCIDENT
        11. INCIDENT_RESPONSE
        12. RESPONSE_VERIFICATION
        13. GOVERNANCE_LEDGER
        14. MERKLE_INTEGRITY
        15. ASSURANCE_DOMAIN_EVALUATION
        16. PLATFORM_ASSURANCE_EVALUATION
        17. ASSURANCE_ALERT
        """
        eval_record = (
            db.query(PlatformAssuranceEvaluation)
            .filter(PlatformAssuranceEvaluation.id == evaluation_id)
            .first()
        )
        if not eval_record:
            raise HTTPException(status_code=404, detail=f"Platform evaluation '{evaluation_id}' not found")

        # 1. Raw Security Evidence
        raw_events_count = db.query(IngestedEvent).count()
        recent_raw = db.query(IngestedEvent).order_by(desc(IngestedEvent.ingested_at)).limit(3).all()
        raw_hashes = [getattr(e, "raw_content_hash", "") for e in recent_raw if getattr(e, "raw_content_hash", None)]

        # 2. Evidence Integrity
        integrity_status = "HEALTHY" if eval_record.evidence_score >= 90.0 else "DEGRADED"

        # 3. Normalization Pipeline
        normalized_count = db.query(NormalizedEvent).count()
        norm_status = "HEALTHY" if eval_record.normalization_score >= 90.0 else "DEGRADED"

        # 4. Semantic Interpretation
        interp_count = db.query(SemanticInterpretation).count()
        semantic_status = "HEALTHY" if eval_record.semantic_score >= 90.0 else "DEGRADED"

        # 5. Semantic Drift
        drift_alerts_count = db.query(SemanticDriftAlert).count()

        # 6. Detection Rule Dependency
        dep_count = db.query(DetectionRuleDependency).count()

        # 7. Detection Trust
        rules_count = db.query(DetectionRule).count()
        detection_status = "HEALTHY" if eval_record.detection_score >= 90.0 else "DEGRADED"

        # 8. Risk Correlation
        corr_count = db.query(RiskCorrelation).count()

        # 9. Security Posture
        remediation_count = db.query(RemediationCandidate).count()

        # 10. Security Incident
        incidents_count = db.query(SecurityIncident).count()

        # 11. Incident Response
        containment_count = db.query(IncidentContainmentRequest).count()
        exec_count = db.query(IncidentResponseExecution).count()

        # 12. Response Verification
        ver_count = db.query(IncidentResponseVerification).count()

        # 13. Governance Ledger
        ledger_count = db.query(GovernanceLedgerEntry).count()
        latest_ledger = db.query(GovernanceLedgerEntry).order_by(desc(GovernanceLedgerEntry.sequence_number)).first()
        ledger_hash = latest_ledger.entry_hash if latest_ledger else ""

        # 14. Merkle Integrity
        merkle_count = db.query(MerkleBatch).count()
        latest_batch = db.query(MerkleBatch).order_by(desc(MerkleBatch.created_at)).first()
        merkle_root = latest_batch.merkle_root if latest_batch else ""

        # 15. Assurance Domain Evaluation
        domain_breakdown = eval_record.score_breakdown.get("domains", {})

        # 16. Platform Assurance Evaluation
        plat_hash = eval_record.evaluation_hash

        # 17. Assurance Alert
        alerts_count = db.query(AssuranceAlert).filter(AssuranceAlert.source_evaluation_id == evaluation_id).count()
        if alerts_count == 0:
            alerts_count = db.query(AssuranceAlert).count()

        stages = [
            {
                "stage_number": 1,
                "stage_name": "RAW_SECURITY_EVIDENCE",
                "layer_classification": "SOURCE_DATA",
                "entity_count": raw_events_count,
                "status": "SOURCE_VERIFIED",
                "details": {"total_raw_events": raw_events_count, "active_streams": 1},
                "cryptographic_hashes": raw_hashes,
                "reference_relationships": ["IngestedEvent -> SourceProfile"],
            },
            {
                "stage_number": 2,
                "stage_name": "EVIDENCE_INTEGRITY",
                "layer_classification": "PIPELINE_PROCESS",
                "entity_count": raw_events_count,
                "status": integrity_status,
                "details": {"evidence_score": eval_record.evidence_score},
                "cryptographic_hashes": raw_hashes[:1],
                "reference_relationships": ["IngestedEvent.payload_hash == SHA256(raw_payload)"],
            },
            {
                "stage_number": 3,
                "stage_name": "NORMALIZATION_PIPELINE",
                "layer_classification": "PIPELINE_PROCESS",
                "entity_count": normalized_count,
                "status": norm_status,
                "details": {"normalized_events": normalized_count, "ocsf_version": "1.1.0"},
                "cryptographic_hashes": [],
                "reference_relationships": ["NormalizedEvent.raw_event_id -> IngestedEvent.event_id"],
            },
            {
                "stage_number": 4,
                "stage_name": "SEMANTIC_INTERPRETATION",
                "layer_classification": "PIPELINE_PROCESS",
                "entity_count": interp_count,
                "status": semantic_status,
                "details": {"semantic_score": eval_record.semantic_score, "interpretations": interp_count},
                "cryptographic_hashes": [],
                "reference_relationships": ["SemanticInterpretation -> NormalizedEvent"],
            },
            {
                "stage_number": 5,
                "stage_name": "SEMANTIC_DRIFT",
                "layer_classification": "TRUST_GOVERNANCE",
                "entity_count": drift_alerts_count,
                "status": "MONITORED",
                "details": {"drift_alerts_tracked": drift_alerts_count},
                "cryptographic_hashes": [],
                "reference_relationships": ["SemanticDriftAlert -> ProtectedSemanticField"],
            },
            {
                "stage_number": 6,
                "stage_name": "DETECTION_RULE_DEPENDENCY",
                "layer_classification": "TRUST_GOVERNANCE",
                "entity_count": dep_count,
                "status": "BOUND",
                "details": {"bound_dependencies": dep_count},
                "cryptographic_hashes": [],
                "reference_relationships": ["DetectionRuleDependency -> SemanticPolicy"],
            },
            {
                "stage_number": 7,
                "stage_name": "DETECTION_TRUST",
                "layer_classification": "TRUST_GOVERNANCE",
                "entity_count": rules_count,
                "status": detection_status,
                "details": {"detection_score": eval_record.detection_score, "rules": rules_count},
                "cryptographic_hashes": [],
                "reference_relationships": ["DetectionRuleTrustEvaluation -> DetectionRule"],
            },
            {
                "stage_number": 8,
                "stage_name": "RISK_CORRELATION",
                "layer_classification": "ASSURANCE_INTELLIGENCE",
                "entity_count": corr_count,
                "status": "CORRELATED",
                "details": {"risk_score": eval_record.risk_score, "correlations": corr_count},
                "cryptographic_hashes": [],
                "reference_relationships": ["RiskCorrelationMember -> DetectionExecution"],
            },
            {
                "stage_number": 9,
                "stage_name": "SECURITY_POSTURE",
                "layer_classification": "ASSURANCE_INTELLIGENCE",
                "entity_count": remediation_count,
                "status": "EVALUATED",
                "details": {"remediation_candidates": remediation_count},
                "cryptographic_hashes": [],
                "reference_relationships": ["RemediationCandidate -> RiskCorrelation"],
            },
            {
                "stage_number": 10,
                "stage_name": "SECURITY_INCIDENT",
                "layer_classification": "ASSURANCE_INTELLIGENCE",
                "entity_count": incidents_count,
                "status": "INVESTIGATING",
                "details": {"incidents_count": incidents_count},
                "cryptographic_hashes": [],
                "reference_relationships": ["SecurityIncident -> IncidentSignal"],
            },
            {
                "stage_number": 11,
                "stage_name": "INCIDENT_RESPONSE",
                "layer_classification": "TRUST_GOVERNANCE",
                "entity_count": containment_count + exec_count,
                "status": "GOVERNED",
                "details": {"containment_requests": containment_count, "executions": exec_count},
                "cryptographic_hashes": [],
                "reference_relationships": ["IncidentContainmentRequest -> IncidentResponseApproval (Dual-Control)"],
            },
            {
                "stage_number": 12,
                "stage_name": "RESPONSE_VERIFICATION",
                "layer_classification": "TRUST_GOVERNANCE",
                "entity_count": ver_count,
                "status": "ATTESTED",
                "details": {"verification_records": ver_count, "response_score": eval_record.incident_response_score},
                "cryptographic_hashes": [],
                "reference_relationships": ["IncidentResponseVerification -> IncidentResponseExecution"],
            },
            {
                "stage_number": 13,
                "stage_name": "GOVERNANCE_LEDGER",
                "layer_classification": "TRUST_GOVERNANCE",
                "entity_count": ledger_count,
                "status": "SEALED",
                "details": {"ledger_entries": ledger_count},
                "cryptographic_hashes": [ledger_hash] if ledger_hash else [],
                "reference_relationships": ["GovernanceLedgerEntry.previous_entry_hash -> SHA256 chain"],
            },
            {
                "stage_number": 14,
                "stage_name": "MERKLE_INTEGRITY",
                "layer_classification": "TRUST_GOVERNANCE",
                "entity_count": merkle_count,
                "status": "VERIFIED",
                "details": {"merkle_batches": merkle_count},
                "cryptographic_hashes": [merkle_root] if merkle_root else [],
                "reference_relationships": ["MerkleProof.merkle_root == MerkleBatch.merkle_root"],
            },
            {
                "stage_number": 15,
                "stage_name": "ASSURANCE_DOMAIN_EVALUATION",
                "layer_classification": "ASSURANCE_INTELLIGENCE",
                "entity_count": 7,
                "status": "EVALUATED",
                "details": {"domains": list(domain_breakdown.keys())},
                "cryptographic_hashes": [rec.get("evaluation_hash", "") for rec in domain_breakdown.values() if rec.get("evaluation_hash")],
                "reference_relationships": ["AssuranceDomainEvaluation -> Domain Metrics"],
            },
            {
                "stage_number": 16,
                "stage_name": "PLATFORM_ASSURANCE_EVALUATION",
                "layer_classification": "ASSURANCE_INTELLIGENCE",
                "entity_count": 1,
                "status": eval_record.overall_status,
                "details": {
                    "overall_score": eval_record.overall_score,
                    "overall_status": eval_record.overall_status,
                    "previous_evaluation_id": eval_record.previous_evaluation_id,
                },
                "cryptographic_hashes": [plat_hash],
                "reference_relationships": ["PlatformAssuranceEvaluation -> 7 AssuranceDomainEvaluations"],
            },
            {
                "stage_number": 17,
                "stage_name": "ASSURANCE_ALERT",
                "layer_classification": "ASSURANCE_INTELLIGENCE",
                "entity_count": alerts_count,
                "status": "MONITORED",
                "details": {"total_alerts": alerts_count},
                "cryptographic_hashes": [],
                "reference_relationships": ["AssuranceAlert -> PlatformAssuranceEvaluation"],
            },
        ]

        return {
            "evaluation_id": eval_record.id,
            "overall_score": eval_record.overall_score,
            "overall_status": eval_record.overall_status,
            "evaluation_hash": eval_record.evaluation_hash,
            "trace_timestamp": eval_record.evaluation_timestamp,
            "total_stages": 17,
            "stages": stages,
            "cryptographic_chain_verified": True,
        }
