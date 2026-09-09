"""
services/scenario_artifact_binding_service.py
---------------------------------------------
Service for binding scenario execution stages to immutable SentinelTrace platform artifacts.
Stores cryptographic references only without mutating or duplicating existing records.

Sprint 10B — End-to-End Security Scenario Orchestration & Cross-Domain Evidence Replay.
Core Invariant: "DEMONSTRATION != SYNTHETIC TRUST. STORE REFERENCES ONLY."
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.security_scenario import (
    ScenarioArtifactBinding,
    SCENARIO_ARTIFACT_BINDING_DOMAIN_PREFIX,
    calculate_scenario_hash,
)

logger = logging.getLogger("sentinel.services.scenario_artifact_binding")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScenarioArtifactBindingService:
    """
    Manages cryptographic binding of scenario execution stages to platform artifacts.
    """

    @staticmethod
    def calculate_binding_hash(
        scenario_execution_id: str,
        stage_execution_id: str,
        artifact_domain: str,
        artifact_type: str,
        artifact_id: str,
        artifact_hash: str,
    ) -> str:
        """
        Calculates deterministic SHA-256 hash for artifact binding.
        Prefix: SENTINELTRACE_SCENARIO_ARTIFACT_BINDING_V1
        """
        payload = {
            "scenario_execution_id": scenario_execution_id,
            "stage_execution_id": stage_execution_id,
            "artifact_domain": artifact_domain,
            "artifact_type": artifact_type,
            "artifact_id": artifact_id,
            "artifact_hash": artifact_hash,
        }
        return calculate_scenario_hash(SCENARIO_ARTIFACT_BINDING_DOMAIN_PREFIX, payload)

    @classmethod
    def bind_artifact(
        cls,
        db: Session,
        scenario_execution_id: str,
        stage_execution_id: str,
        artifact_domain: str,
        artifact_type: str,
        artifact_id: str,
        artifact_hash: str,
        artifact_reference_json: Optional[Dict[str, Any]] = None,
    ) -> ScenarioArtifactBinding:
        """
        Creates and persists a cryptographic reference binding.
        """
        ref_json = artifact_reference_json or {}
        binding_hash = cls.calculate_binding_hash(
            scenario_execution_id=scenario_execution_id,
            stage_execution_id=stage_execution_id,
            artifact_domain=artifact_domain,
            artifact_type=artifact_type,
            artifact_id=str(artifact_id),
            artifact_hash=artifact_hash,
        )

        binding = ScenarioArtifactBinding(
            id=f"sab_{uuid.uuid4().hex[:16]}",
            scenario_execution_id=scenario_execution_id,
            stage_execution_id=stage_execution_id,
            artifact_domain=artifact_domain,
            artifact_type=artifact_type,
            artifact_id=str(artifact_id),
            artifact_hash=artifact_hash,
            artifact_reference_json=ref_json,
            binding_hash=binding_hash,
            created_at=utcnow(),
        )

        db.add(binding)
        db.flush()
        logger.info(
            f"Bound artifact [{artifact_domain}:{artifact_type}:{artifact_id}] "
            f"to stage {stage_execution_id} in execution {scenario_execution_id}"
        )
        return binding

    @staticmethod
    def get_stage_artifacts(db: Session, stage_execution_id: str) -> List[ScenarioArtifactBinding]:
        """Returns all artifact bindings for a specific stage execution."""
        return (
            db.query(ScenarioArtifactBinding)
            .filter(ScenarioArtifactBinding.stage_execution_id == stage_execution_id)
            .order_by(ScenarioArtifactBinding.created_at.asc())
            .all()
        )

    @staticmethod
    def get_execution_artifacts(db: Session, scenario_execution_id: str) -> List[ScenarioArtifactBinding]:
        """Returns all artifact bindings across all stages of a scenario execution."""
        return (
            db.query(ScenarioArtifactBinding)
            .filter(ScenarioArtifactBinding.scenario_execution_id == scenario_execution_id)
            .order_by(ScenarioArtifactBinding.created_at.asc())
            .all()
        )

    @classmethod
    def verify_artifact_binding(cls, binding: ScenarioArtifactBinding) -> bool:
        """
        Verifies that a binding's stored hash matches its recalculation.
        """
        expected_hash = cls.calculate_binding_hash(
            scenario_execution_id=binding.scenario_execution_id,
            stage_execution_id=binding.stage_execution_id,
            artifact_domain=binding.artifact_domain,
            artifact_type=binding.artifact_type,
            artifact_id=binding.artifact_id,
            artifact_hash=binding.artifact_hash,
        )
        return binding.binding_hash == expected_hash

    @classmethod
    def verify_execution_artifacts(cls, db: Session, scenario_execution_id: str) -> Tuple[bool, List[str]]:
        """
        Verifies all artifact bindings for an execution.
        Returns (is_valid, list_of_error_messages).
        """
        bindings = cls.get_execution_artifacts(db, scenario_execution_id)
        errors = []

        for b in bindings:
            if not cls.verify_artifact_binding(b):
                errors.append(
                    f"Artifact binding hash mismatch for binding {b.id} "
                    f"[{b.artifact_domain}:{b.artifact_type}:{b.artifact_id}]"
                )

        return (len(errors) == 0, errors)
