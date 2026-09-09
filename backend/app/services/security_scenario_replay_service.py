"""
services/security_scenario_replay_service.py
--------------------------------------------
Service for reconstructing historical evidence timelines and executing controlled
scenario replays without mutating original immutable platform records.

Sprint 10B — End-to-End Security Scenario Orchestration & Cross-Domain Evidence Replay.
Core Invariants: "REPLAY != RECOMPUTATION WITHOUT PROOF. UNKNOWN != IDENTICAL."
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.security_scenario import (
    ScenarioExecution,
    ScenarioStageExecution,
    ScenarioArtifactBinding,
    ScenarioVerificationResult,
    SCENARIO_REPLAY_DOMAIN_PREFIX,
    calculate_scenario_hash,
)
from app.services.scenario_artifact_binding_service import ScenarioArtifactBindingService
from app.services.governance_ledger_service import GovernanceLedgerService

logger = logging.getLogger("sentinel.services.scenario_replay")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SecurityScenarioReplayService:
    """
    Handles immutable timeline reconstruction and controlled scenario replay comparisons.
    """

    @classmethod
    def reconstruct_timeline(cls, db: Session, execution_id: str) -> List[Dict[str, Any]]:
        """
        Reconstructs the full chronological timeline from immutable artifact references
        without modifying or creating new artifacts.
        """
        execution = db.query(ScenarioExecution).filter(ScenarioExecution.id == execution_id).first()
        if not execution:
            raise ValueError(f"ScenarioExecution '{execution_id}' not found.")

        stages = (
            db.query(ScenarioStageExecution)
            .filter(ScenarioStageExecution.scenario_execution_id == execution_id)
            .order_by(ScenarioStageExecution.stage_number.asc())
            .all()
        )

        timeline = []
        for s in stages:
            bindings = ScenarioArtifactBindingService.get_stage_artifacts(db, s.id)
            binding_items = [
                {
                    "binding_id": b.id,
                    "artifact_domain": b.artifact_domain,
                    "artifact_type": b.artifact_type,
                    "artifact_id": b.artifact_id,
                    "artifact_hash": b.artifact_hash,
                    "binding_hash": b.binding_hash,
                }
                for b in bindings
            ]

            timeline.append({
                "stage_number": s.stage_number,
                "stage_key": s.stage_key,
                "stage_name": s.stage_name,
                "status": s.status,
                "verification_result": s.verification_result,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "artifacts": binding_items,
                "output_data": s.output_reference_json,
                "execution_hash": s.execution_hash,
            })

        return timeline

    @classmethod
    def compare_executions(
        cls,
        db: Session,
        original_execution_id: str,
        replay_execution_id: str,
    ) -> Dict[str, Any]:
        """
        Compares original execution vs replay execution.
        Classifies result: IDENTICAL, FUNCTIONALLY_EQUIVALENT, DIFFERENT, INCONCLUSIVE.
        """
        orig = db.query(ScenarioExecution).filter(ScenarioExecution.id == original_execution_id).first()
        repl = db.query(ScenarioExecution).filter(ScenarioExecution.id == replay_execution_id).first()

        if not orig or not repl:
            return {
                "comparison_status": "INCONCLUSIVE",
                "divergent_stages": [],
                "summary": "One or both execution records not found.",
                "identical_hashes": False,
            }

        orig_stages = (
            db.query(ScenarioStageExecution)
            .filter(ScenarioStageExecution.scenario_execution_id == original_execution_id)
            .order_by(ScenarioStageExecution.stage_number.asc())
            .all()
        )
        repl_stages = (
            db.query(ScenarioStageExecution)
            .filter(ScenarioStageExecution.scenario_execution_id == replay_execution_id)
            .order_by(ScenarioStageExecution.stage_number.asc())
            .all()
        )

        if len(orig_stages) != len(repl_stages):
            return {
                "comparison_status": "DIFFERENT",
                "divergent_stages": [{"error": f"Stage count mismatch: {len(orig_stages)} vs {len(repl_stages)}"}],
                "summary": "Replay execution contains a different number of stages than original.",
                "identical_hashes": False,
            }

        divergent_stages = []
        same_hash_count = 0

        for os, rs in zip(orig_stages, repl_stages):
            is_same_key = os.stage_key == rs.stage_key
            is_same_verif = os.verification_result == rs.verification_result
            is_same_status = os.status == rs.status

            orig_bindings = ScenarioArtifactBindingService.get_stage_artifacts(db, os.id)
            repl_bindings = ScenarioArtifactBindingService.get_stage_artifacts(db, rs.id)

            orig_hashes = [b.artifact_hash for b in orig_bindings]
            repl_hashes = [b.artifact_hash for b in repl_bindings]

            hashes_match = orig_hashes == repl_hashes
            if hashes_match:
                same_hash_count += 1

            if not (is_same_key and is_same_verif and is_same_status):
                divergent_stages.append({
                    "stage_number": os.stage_number,
                    "stage_key": os.stage_key,
                    "original_status": os.status,
                    "replay_status": rs.status,
                    "original_verification": os.verification_result,
                    "replay_verification": rs.verification_result,
                })

        if len(divergent_stages) == 0 and same_hash_count == len(orig_stages):
            comparison_status = "IDENTICAL"
            summary = "Replay execution produced exact identical artifact hashes and stage states."
        elif len(divergent_stages) == 0:
            comparison_status = "FUNCTIONALLY_EQUIVALENT"
            summary = "Replay execution achieved identical verification and stage states with new execution seeds."
        else:
            comparison_status = "DIFFERENT"
            summary = f"Divergence detected in {len(divergent_stages)} stages between original and replay."

        return {
            "comparison_status": comparison_status,
            "divergent_stages": divergent_stages,
            "summary": summary,
            "identical_hashes": same_hash_count == len(orig_stages),
        }

    @classmethod
    def replay_execution(
        cls,
        db: Session,
        original_execution_id: str,
        replay_mode: str = "HISTORICAL_REPLAY",
        actor_id: str = "system",
        actor_username: str = "system",
        verify_against_original: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes a controlled replay of a scenario.
        """
        orig = db.query(ScenarioExecution).filter(ScenarioExecution.id == original_execution_id).first()
        if not orig:
            raise ValueError(f"Original execution '{original_execution_id}' not found.")

        # Import locally to prevent circular import
        from app.services.security_scenario_orchestration_service import SecurityScenarioOrchestrationService

        if replay_mode == "EVIDENCE_REPLAY":
            # Reconstruct timeline only
            timeline = cls.reconstruct_timeline(db, original_execution_id)
            is_valid, _ = ScenarioArtifactBindingService.verify_execution_artifacts(db, original_execution_id)

            GovernanceLedgerService.append_entry(
                db=db,
                event_type="SCENARIO_REPLAY_REQUESTED",
                actor_id=actor_id,
                actor_username=actor_username,
                payload={
                    "entity_type": "SCENARIO_EXECUTION",
                    "entity_id": original_execution_id,
                    "mode": "EVIDENCE_REPLAY",
                    "integrity_verified": is_valid,
                },
            )

            return {
                "original_execution_id": original_execution_id,
                "replay_execution_id": None,
                "replay_mode": "EVIDENCE_REPLAY",
                "comparison_status": "IDENTICAL" if is_valid else "DIFFERENT",
                "divergent_stages": [],
                "reconstructed_timeline": timeline,
                "integrity_verified": is_valid,
                "summary": "Evidence timeline successfully reconstructed from immutable artifact bindings.",
            }

        # CONTROLLED_REEXECUTION or HISTORICAL_REPLAY with new execution run
        new_exec = SecurityScenarioOrchestrationService.create_execution(
            db=db,
            scenario_id_or_key=orig.scenario_id,
            version_id=orig.scenario_version_id,
            execution_mode=replay_mode,
            initiated_by_user_id=actor_id,
            deterministic_seed_override=f"{orig.deterministic_execution_seed}_REPLAY",
            notes=f"Replay run for {orig.execution_number}",
        )

        # Run all stages
        SecurityScenarioOrchestrationService.execute_all_stages(
            db=db,
            execution_id=new_exec.id,
            actor_id=actor_id,
            actor_username=actor_username,
        )

        comparison = cls.compare_executions(db, original_execution_id, new_exec.id)
        timeline = cls.reconstruct_timeline(db, new_exec.id)

        GovernanceLedgerService.append_entry(
            db=db,
            event_type="SCENARIO_REPLAY_VERIFIED",
            actor_id=actor_id,
            actor_username=actor_username,
            payload={
                "entity_type": "SCENARIO_EXECUTION",
                "entity_id": new_exec.id,
                "original_execution_id": original_execution_id,
                "replay_execution_id": new_exec.id,
                "comparison_status": comparison["comparison_status"],
            },
        )

        return {
            "original_execution_id": original_execution_id,
            "replay_execution_id": new_exec.id,
            "replay_mode": replay_mode,
            "comparison_status": comparison["comparison_status"],
            "divergent_stages": comparison["divergent_stages"],
            "reconstructed_timeline": timeline,
            "integrity_verified": comparison["comparison_status"] in ("IDENTICAL", "FUNCTIONALLY_EQUIVALENT"),
            "summary": comparison["summary"],
        }
