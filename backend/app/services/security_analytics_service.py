"""
services/security_analytics_service.py
--------------------------------------
Unified Security Analytics Snapshot, Scoring & Telemetry Engine.

Sprint 12B — Security Analytics, Reporting & Evidence Intelligence.
Core Invariant: "SECURITY METRICS WITHOUT EVIDENCE ARE NUMBERS.
SECURITY METRICS WITH TRACEABLE EVIDENCE BECOME INTELLIGENCE."
"""

from datetime import datetime, timezone, timedelta
import uuid
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.security_analytics import (
    SecurityAnalyticsSnapshot,
    SecurityMetricDefinition,
    SecurityMetricEvaluation,
    ANALYTICS_SNAPSHOT_DOMAIN_PREFIX,
    compute_canonical_hash,
)
from app.services.security_metric_registry_service import SecurityMetricRegistryService


class SecurityAnalyticsService:
    """
    Orchestrates point-in-time cross-domain security analytics snapshots.
    """

    @staticmethod
    def create_snapshot(
        db: Session,
        period_type: str = "24H",
        created_by: str = "SYSTEM",
        period_start: Optional[datetime] = None,
        period_end: Optional[datetime] = None,
        cryptographic_failure_detected: bool = False,
    ) -> SecurityAnalyticsSnapshot:
        """
        Builds, evaluates, scores, and cryptographically seals a SecurityAnalyticsSnapshot.
        """
        now = datetime.now(timezone.utc)
        if not period_end:
            period_end = now
        if not period_start:
            if period_type == "24H":
                period_start = period_end - timedelta(hours=24)
            elif period_type == "7D":
                period_start = period_end - timedelta(days=7)
            elif period_type == "30D":
                period_start = period_end - timedelta(days=30)
            elif period_type == "90D":
                period_start = period_end - timedelta(days=90)
            else:
                period_start = period_end - timedelta(hours=24)

        # Ensure metrics are seeded
        defs = SecurityMetricRegistryService.seed_default_metrics(db)

        snapshot_count = db.query(SecurityAnalyticsSnapshot).count()
        snapshot_num = f"SAS-2026-{(snapshot_count + 1):03d}"

        # 1. Evaluate all metrics
        evaluations_to_add: List[SecurityMetricEvaluation] = []
        required_count = 0
        available_required_count = 0
        domains_set = set()
        unknown_domains_set = set()
        critical_count = 0
        high_count = 0
        total_metric_score_sum = 0.0

        for metric_def in defs:
            domains_set.add(metric_def.domain)
            if metric_def.requires_complete_telemetry:
                required_count += 1

            eval_res = SecurityMetricRegistryService.evaluate_metric(
                db, metric_def, period_start, period_end
            )

            if eval_res["telemetry_state"] == "COMPLETE":
                if metric_def.requires_complete_telemetry:
                    available_required_count += 1
            elif eval_res["telemetry_state"] == "PARTIAL":
                if metric_def.requires_complete_telemetry:
                    available_required_count += 0.5
            elif eval_res["telemetry_state"] in ("INSUFFICIENT", "UNKNOWN"):
                unknown_domains_set.add(metric_def.domain)

            if eval_res["metric_status"] == "CRITICAL":
                critical_count += 1
            elif eval_res["metric_status"] == "DEGRADED":
                high_count += 1

            # Metric score normalization for overall calculation
            m_val = eval_res["metric_value"]
            if metric_def.direction == "LOWER_IS_BETTER":
                # Invert for score calculation where 0 is 100 points
                score_contrib = max(0.0, 100.0 - min(100.0, m_val * 10.0 if metric_def.unit == "COUNT" else m_val))
            elif metric_def.direction == "HIGHER_IS_BETTER":
                score_contrib = min(100.0, max(0.0, m_val))
            else:
                score_contrib = 85.0
            total_metric_score_sum += score_contrib

            eval_record = SecurityMetricEvaluation(
                snapshot_id="",  # Bound below
                metric_definition_id=metric_def.id,
                metric_value=eval_res["metric_value"],
                metric_status=eval_res["metric_status"],
                confidence_score=eval_res["confidence_score"],
                sample_count=eval_res["sample_count"],
                telemetry_state=eval_res["telemetry_state"],
                calculation_details_json=eval_res["calculation_details_json"],
                source_references_json=eval_res["source_references_json"],
                evaluation_hash=eval_res["evaluation_hash"],
            )
            evaluations_to_add.append(eval_record)

        # 2. Telemetry Completeness
        completeness = round((available_required_count / max(1, required_count)) * 100.0, 1)
        completeness = max(0.0, min(100.0, completeness))

        # 3. Overall Analytics Confidence Deductions
        confidence = 100.0
        if completeness < 100.0 and completeness >= 75.0:
            confidence -= 15.0
        elif completeness < 75.0:
            confidence -= 30.0

        if len(unknown_domains_set) > 0:
            confidence -= (len(unknown_domains_set) * 10.0)

        if cryptographic_failure_detected:
            confidence = 0.0  # Cryptographic Dominance Rule

        confidence = max(0.0, min(100.0, round(confidence, 1)))

        # 4. Overall Security Score
        overall_sec_score = round(total_metric_score_sum / max(1, len(defs)), 1)
        if cryptographic_failure_detected:
            overall_sec_score = min(20.0, overall_sec_score)

        # 5. Snapshot Hash
        snapshot_id = f"sas-{uuid.uuid4().hex[:12]}"
        snap_payload = {
            "id": snapshot_id,
            "snapshot_number": snapshot_num,
            "period_type": period_type,
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "overall_security_score": overall_sec_score,
            "overall_confidence": confidence,
            "telemetry_completeness": completeness,
            "domains_evaluated": len(domains_set),
            "critical_findings": critical_count,
        }
        snap_hash = compute_canonical_hash(ANALYTICS_SNAPSHOT_DOMAIN_PREFIX, snap_payload)

        # Create entity
        snapshot = SecurityAnalyticsSnapshot(
            id=snapshot_id,
            snapshot_number=snapshot_num,
            period_type=period_type,
            period_start=period_start,
            period_end=period_end,
            overall_security_score=overall_sec_score,
            overall_confidence=confidence,
            telemetry_completeness=completeness,
            domains_evaluated=len(domains_set),
            domains_unknown=len(unknown_domains_set),
            critical_findings=critical_count,
            high_findings=high_count,
            snapshot_hash=snap_hash,
            created_at=now,
            created_by=created_by,
        )
        db.add(snapshot)
        db.flush()

        for ev in evaluations_to_add:
            ev.snapshot_id = snapshot.id
            db.add(ev)

        db.commit()

        # Trigger Trend, Insight, and Provenance services
        from app.services.security_trend_service import SecurityTrendService
        from app.services.security_analytics_insight_service import SecurityAnalyticsInsightService
        from app.services.security_analytics_provenance_service import SecurityAnalyticsProvenanceService

        SecurityTrendService.compute_trends_for_snapshot(db, snapshot.id)
        SecurityAnalyticsInsightService.generate_insights_for_snapshot(db, snapshot.id)
        SecurityAnalyticsProvenanceService.generate_provenance_chain(db, snapshot.id)

        db.refresh(snapshot)
        return snapshot

    @staticmethod
    def get_latest_snapshot(db: Session) -> Optional[SecurityAnalyticsSnapshot]:
        latest = db.query(SecurityAnalyticsSnapshot).order_by(
            SecurityAnalyticsSnapshot.created_at.desc()
        ).first()
        if not latest:
            latest = SecurityAnalyticsService.create_snapshot(db, "24H", "SYSTEM")
        return latest

    @staticmethod
    def get_snapshot_by_id(db: Session, snapshot_id: str) -> Optional[SecurityAnalyticsSnapshot]:
        return db.query(SecurityAnalyticsSnapshot).filter_by(id=snapshot_id).first()

    @staticmethod
    def list_snapshots(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        period_type: Optional[str] = None,
    ) -> List[SecurityAnalyticsSnapshot]:
        q = db.query(SecurityAnalyticsSnapshot)
        if period_type:
            q = q.filter_by(period_type=period_type)
        return q.order_by(SecurityAnalyticsSnapshot.created_at.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_dashboard_summary(db: Session) -> Dict[str, Any]:
        """
        Aggregated summary KPIs for the Security Analytics Command Center.
        """
        latest = SecurityAnalyticsService.get_latest_snapshot(db)
        total_snapshots = db.query(SecurityAnalyticsSnapshot).count()
        defs_count = db.query(SecurityMetricDefinition).count()

        return {
            "latest_snapshot_id": latest.id if latest else None,
            "latest_snapshot_number": latest.snapshot_number if latest else "SAS-2026-000",
            "overall_security_score": latest.overall_security_score if latest else 88.0,
            "overall_confidence": latest.overall_confidence if latest else 100.0,
            "telemetry_completeness": latest.telemetry_completeness if latest else 100.0,
            "domains_evaluated": latest.domains_evaluated if latest else 15,
            "critical_findings": latest.critical_findings if latest else 0,
            "high_findings": latest.high_findings if latest else 0,
            "total_snapshots": total_snapshots,
            "total_metric_definitions": defs_count,
            "snapshot_hash": latest.snapshot_hash if latest else None,
            "created_at": latest.created_at.isoformat() if latest else None,
        }
