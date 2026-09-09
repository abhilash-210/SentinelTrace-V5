"""
services/investigation_priority_service.py
------------------------------------------
Deterministic Case Prioritization Engine with Cryptographic Hard Failure Dominance.

Sprint 12A — Unified SOC Investigation & Security Case Management.
Core Invariant: "CRYPTOGRAPHIC FAILURE STRICTLY OVERRIDES NUMERICAL AVERAGES."
"""

from typing import Any, Dict, List, Optional, Tuple


class InvestigationPriorityService:
    """
    Computes deterministic priority scores and classifications for SOC investigations.
    """

    @staticmethod
    def calculate_priority(
        severity: str = "MEDIUM",
        risk_score: float = 50.0,
        threat_confidence: float = 0.5,
        asset_criticality: str = "MEDIUM",
        impact_score: float = 20.0,
        cryptographic_integrity_verified: bool = True,
    ) -> Dict[str, Any]:
        """
        Calculates explainable priority score (0.0 to 100.0) and priority level.
        Hard Rule: Cryptographic integrity failure immediately forces CRITICAL priority.
        """
        drivers: List[str] = []

        # 1. Cryptographic Dominance Check
        if not cryptographic_integrity_verified:
            return {
                "priority_score": 100.0,
                "priority": "CRITICAL",
                "drivers": [
                    "CRITICAL: Cryptographic integrity violation / content tampering detected in bound artifacts.",
                    "Hard failure override activated — all numerical scoring bypassed.",
                ],
                "hard_failure_override": True,
                "components": {
                    "severity_points": 0.0,
                    "risk_points": 0.0,
                    "threat_points": 0.0,
                    "asset_points": 0.0,
                    "impact_points": 0.0,
                },
            }

        # 2. Severity Factor (Max 30.0)
        sev_upper = severity.upper().strip()
        if sev_upper == "CRITICAL":
            sev_pts = 30.0
            drivers.append("Critical severity security signal (+30.0)")
        elif sev_upper == "HIGH":
            sev_pts = 22.5
            drivers.append("High severity security signal (+22.5)")
        elif sev_upper == "MEDIUM":
            sev_pts = 15.0
            drivers.append("Medium severity baseline (+15.0)")
        elif sev_upper == "LOW":
            sev_pts = 7.5
            drivers.append("Low severity telemetry (+7.5)")
        else:
            sev_pts = 2.0
            drivers.append("Informational severity (+2.0)")

        # 3. Risk Factor (Max 25.0)
        # risk_score is 0-100, mapped to 0-25
        clamped_risk = max(0.0, min(100.0, float(risk_score)))
        risk_pts = round((clamped_risk / 100.0) * 25.0, 2)
        if risk_pts >= 20.0:
            drivers.append(f"Elevated risk concentration (Score: {clamped_risk:.1f} -> +{risk_pts})")
        elif risk_pts >= 12.0:
            drivers.append(f"Moderate risk correlation (Score: {clamped_risk:.1f} -> +{risk_pts})")
        else:
            drivers.append(f"Baseline risk level (+{risk_pts})")

        # 4. Threat Confidence Factor (Max 20.0)
        # threat_confidence is 0.0 - 1.0, mapped to 0-20
        clamped_threat = max(0.0, min(1.0, float(threat_confidence)))
        threat_pts = round(clamped_threat * 20.0, 2)
        if threat_pts >= 15.0:
            drivers.append(f"High-confidence threat intelligence attribution (+{threat_pts})")
        elif threat_pts >= 8.0:
            drivers.append(f"Correlated adversary/IOC threat intelligence (+{threat_pts})")
        else:
            drivers.append(f"Low/unverified threat intelligence confidence (+{threat_pts})")

        # 5. Asset Criticality Factor (Max 15.0)
        crit_upper = asset_criticality.upper().strip()
        if crit_upper == "CRITICAL":
            asset_pts = 15.0
            drivers.append("Target asset classified as Mission Critical Tier-0 (+15.0)")
        elif crit_upper == "HIGH":
            asset_pts = 10.0
            drivers.append("High criticality production asset (+10.0)")
        elif crit_upper == "MEDIUM":
            asset_pts = 5.0
            drivers.append("Standard business asset (+5.0)")
        else:
            asset_pts = 2.0
            drivers.append("Non-critical / development asset (+2.0)")

        # 6. Impact Factor (Max 10.0)
        # impact_score is 0-100, mapped to 0-10
        clamped_impact = max(0.0, min(100.0, float(impact_score)))
        impact_pts = round((clamped_impact / 100.0) * 10.0, 2)
        if impact_pts >= 7.0:
            drivers.append(f"Severe potential business/CIA impact (+{impact_pts})")
        else:
            drivers.append(f"Assessed environmental impact (+{impact_pts})")

        # Calculate Total Score
        total_score = round(sev_pts + risk_pts + threat_pts + asset_pts + impact_pts, 1)
        total_score = max(0.0, min(100.0, total_score))

        # Determine Priority Level
        if total_score >= 85.0:
            priority = "CRITICAL"
        elif total_score >= 65.0:
            priority = "HIGH"
        elif total_score >= 40.0:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        return {
            "priority_score": total_score,
            "priority": priority,
            "drivers": drivers,
            "hard_failure_override": False,
            "components": {
                "severity_points": sev_pts,
                "risk_points": risk_pts,
                "threat_points": threat_pts,
                "asset_points": asset_pts,
                "impact_points": impact_pts,
            },
        }
