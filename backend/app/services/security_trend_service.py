"""
services/security_trend_service.py
----------------------------------
Deterministic Historical Trend Analysis Engine with Metric Direction Awareness.

Sprint 12B — Security Analytics, Reporting & Evidence Intelligence.
Core Invariant: "MISSING TELEMETRY OR LACK OF HISTORICAL BASELINE MUST RETURN INSUFFICIENT_DATA, NEVER FABRICATE STABILITY."
"""

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.security_analytics import (
    SecurityAnalyticsSnapshot,
    SecurityMetricDefinition,
    SecurityMetricEvaluation,
    SecurityTrendSnapshot,
)


class SecurityTrendService:
    """
    Computes mathematical delta and direction-aware trend classifications between snapshots.
    """

    @staticmethod
    def compute_trends_for_snapshot(
        db: Session,
        current_snapshot_id: str,
    ) -> List[SecurityTrendSnapshot]:
        """
        Calculates historical delta against the immediate preceding snapshot.
        """
        current_snap = db.query(SecurityAnalyticsSnapshot).filter_by(id=current_snapshot_id).first()
        if not current_snap:
            return []

        # Find previous snapshot
        prev_snap = db.query(SecurityAnalyticsSnapshot).filter(
            SecurityAnalyticsSnapshot.created_at < current_snap.created_at
        ).order_by(SecurityAnalyticsSnapshot.created_at.desc()).first()

        metric_defs = db.query(SecurityMetricDefinition).all()
        created_trends: List[SecurityTrendSnapshot] = []

        for m_def in metric_defs:
            curr_eval = db.query(SecurityMetricEvaluation).filter_by(
                snapshot_id=current_snap.id,
                metric_definition_id=m_def.id,
            ).first()

            if not curr_eval:
                continue

            curr_val = curr_eval.metric_value
            prev_val: Optional[float] = None
            delta_val: Optional[float] = None
            delta_pct: Optional[float] = None
            classification = "INSUFFICIENT_DATA"
            confidence = 100.0
            reasoning: Dict[str, Any] = {}

            if prev_snap is None:
                classification = "INSUFFICIENT_DATA"
                confidence = 60.0
                reasoning = {
                    "rule": "NO_PREVIOUS_SNAPSHOT",
                    "explanation": "No prior historical baseline exists for delta comparison.",
                }
            elif curr_eval.telemetry_state in ("INSUFFICIENT", "UNKNOWN"):
                classification = "INSUFFICIENT_DATA"
                confidence = 50.0
                reasoning = {
                    "rule": "INCOMPLETE_TELEMETRY",
                    "explanation": f"Current metric telemetry state '{curr_eval.telemetry_state}' precludes trend inference.",
                }
            else:
                prev_eval = db.query(SecurityMetricEvaluation).filter_by(
                    snapshot_id=prev_snap.id,
                    metric_definition_id=m_def.id,
                ).first()

                if prev_eval is None or prev_eval.telemetry_state in ("INSUFFICIENT", "UNKNOWN"):
                    classification = "INSUFFICIENT_DATA"
                    confidence = 60.0
                    reasoning = {
                        "rule": "PREVIOUS_TELEMETRY_MISSING",
                        "explanation": "Previous snapshot lacks valid evaluation telemetry for this metric.",
                    }
                else:
                    prev_val = prev_eval.metric_value
                    delta_val = round(curr_val - prev_val, 2)
                    if prev_val != 0.0:
                        delta_pct = round((delta_val / abs(prev_val)) * 100.0, 1)
                    else:
                        delta_pct = 100.0 if delta_val > 0 else (0.0 if delta_val == 0 else -100.0)

                    # Direction-aware trend classification
                    direction = m_def.direction.upper()
                    if direction == "HIGHER_IS_BETTER":
                        if delta_val > 0.01:
                            classification = "IMPROVING"
                        elif delta_val < -0.01:
                            classification = "DEGRADING"
                        else:
                            classification = "STABLE"
                    elif direction == "LOWER_IS_BETTER":
                        if delta_val < -0.01:
                            classification = "IMPROVING"
                        elif delta_val > 0.01:
                            classification = "DEGRADING"
                        else:
                            classification = "STABLE"
                    else:  # NEUTRAL
                        classification = "STABLE"

                    reasoning = {
                        "rule": f"DIRECTION_{direction}",
                        "current_value": curr_val,
                        "previous_value": prev_val,
                        "delta": delta_val,
                        "delta_percentage": delta_pct,
                        "direction": direction,
                    }

            trend_record = SecurityTrendSnapshot(
                id=f"sts-{uuid.uuid4().hex[:12]}",
                metric_definition_id=m_def.id,
                current_snapshot_id=current_snap.id,
                previous_snapshot_id=prev_snap.id if prev_snap else None,
                current_value=curr_val,
                previous_value=prev_val,
                delta_value=delta_val,
                delta_percentage=delta_pct,
                trend_classification=classification,
                confidence=confidence,
                reasoning_json=reasoning,
                created_at=datetime.now(timezone.utc),
            )
            db.add(trend_record)
            created_trends.append(trend_record)

        db.commit()
        return created_trends

    @staticmethod
    def get_trends_for_snapshot(db: Session, snapshot_id: str) -> List[SecurityTrendSnapshot]:
        return db.query(SecurityTrendSnapshot).filter_by(
            current_snapshot_id=snapshot_id
        ).all()

    @staticmethod
    def get_trend_for_metric(db: Session, metric_code: str) -> Optional[SecurityTrendSnapshot]:
        m_def = db.query(SecurityMetricDefinition).filter_by(metric_code=metric_code).first()
        if not m_def:
            return None
        return db.query(SecurityTrendSnapshot).filter_by(
            metric_definition_id=m_def.id
        ).order_by(SecurityTrendSnapshot.created_at.desc()).first()
