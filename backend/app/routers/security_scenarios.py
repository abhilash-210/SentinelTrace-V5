"""
routers/security_scenarios.py
-----------------------------
FastAPI router for End-to-End Security Scenario Orchestration,
Demonstration Validation, Cross-Domain Evidence Replay & Verification.

Sprint 10B — End-to-End Security Scenario Orchestration, Demonstration Validation & Cross-Domain Evidence Replay.
Prefix: /api/v1/security-scenarios
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.models.security_scenario import (
    SecurityScenario,
    SecurityScenarioVersion,
    ScenarioExecution,
    ScenarioStageExecution,
    ScenarioArtifactBinding,
    ScenarioVerificationResult,
    ScenarioExecutiveImpact,
)
from app.schemas.security_scenario import (
    SecurityScenarioCreate,
    SecurityScenarioResponse,
    SecurityScenarioVersionCreate,
    SecurityScenarioVersionResponse,
    ScenarioExecutionCreateRequest,
    ScenarioExecutionResponse,
    ScenarioStageResponse,
    ScenarioArtifactBindingResponse,
    ScenarioVerificationResponse,
    ScenarioReplayRequest,
    ScenarioReplayResponse,
    ScenarioExecutiveImpactResponse,
    ScenarioProvenanceNode,
    ScenarioDashboardSummary,
    ScenarioVerifyRequest,
)
from app.services.security_scenario_orchestration_service import SecurityScenarioOrchestrationService
from app.services.scenario_artifact_binding_service import ScenarioArtifactBindingService
from app.services.security_scenario_verification_service import SecurityScenarioVerificationService
from app.services.security_scenario_replay_service import SecurityScenarioReplayService
from app.services.scenario_executive_impact_service import ScenarioExecutiveImpactService
from app.services.security_scenario_provenance_service import SecurityScenarioProvenanceService

router = APIRouter(
    prefix="/api/v1/security-scenarios",
    tags=["Security Scenario Orchestration"],
)


@router.post(
    "/seed-defaults",
    response_model=List[SecurityScenarioResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Seed 4 Default Demonstration Scenarios",
)
def seed_default_scenarios(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_CREATE)),
):
    """Seeds the 4 canonical demonstration scenarios required for Sprint 10B."""
    return SecurityScenarioOrchestrationService.seed_default_scenarios(
        db=db,
        system_user_id=current_user.username,
    )


@router.get(
    "/",
    response_model=List[SecurityScenarioResponse],
    summary="List Security Scenarios",
)
def list_scenarios(
    category: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_READ)),
):
    """Lists registered security scenarios."""
    scenarios = SecurityScenarioOrchestrationService.list_scenarios(
        db=db, category=category, status=status, limit=limit, offset=offset
    )
    if not scenarios and offset == 0 and not category:
        # Seed default demonstration scenarios if table is completely empty
        scenarios = SecurityScenarioOrchestrationService.seed_default_scenarios(
            db=db, system_user_id=current_user.username
        )
    return scenarios


@router.post(
    "/",
    response_model=SecurityScenarioResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Security Scenario",
)
def create_scenario(
    request: SecurityScenarioCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_CREATE)),
):
    """Creates a new security scenario definition with initial Version 1."""
    try:
        scenario, _ = SecurityScenarioOrchestrationService.create_scenario(
            db=db,
            scenario_key=request.scenario_key,
            scenario_name=request.scenario_name,
            description=request.description,
            category=request.category.value,
            severity=request.severity.value,
            status=request.status.value,
            created_by_user_id=current_user.username,
        )
        return scenario
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.get(
    "/dashboard/summary",
    response_model=ScenarioDashboardSummary,
    summary="Scenario Command Center KPIs",
)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_READ)),
):
    """Returns aggregated metrics for the Security Scenario Command Center."""
    total_scenarios = db.query(func.count(SecurityScenario.id)).scalar() or 0
    active_scenarios = db.query(func.count(SecurityScenario.id)).filter(SecurityScenario.status == "ACTIVE").scalar() or 0
    total_executions = db.query(func.count(ScenarioExecution.id)).scalar() or 0
    completed_executions = db.query(func.count(ScenarioExecution.id)).filter(ScenarioExecution.status == "COMPLETED").scalar() or 0
    verified_executions = db.query(func.count(ScenarioExecution.id)).filter(ScenarioExecution.verification_status == "VERIFIED").scalar() or 0
    degraded_executions = db.query(func.count(ScenarioExecution.id)).filter(ScenarioExecution.verification_status == "DEGRADED").scalar() or 0
    failed_executions = db.query(func.count(ScenarioExecution.id)).filter(ScenarioExecution.verification_status == "FAILED").scalar() or 0

    integrity_rate = (verified_executions / completed_executions * 100.0) if completed_executions > 0 else 100.0

    recent_execs = (
        db.query(ScenarioExecution)
        .order_by(ScenarioExecution.started_at.desc())
        .limit(5)
        .all()
    )

    recent_data = [
        {
            "id": e.id,
            "execution_number": e.execution_number,
            "scenario_key": e.scenario.scenario_key if e.scenario else "UNKNOWN",
            "mode": e.execution_mode,
            "status": e.status,
            "verification_status": e.verification_status,
            "started_at": e.started_at.isoformat() if e.started_at else None,
        }
        for e in recent_execs
    ]

    return {
        "total_scenarios": total_scenarios,
        "active_scenarios": active_scenarios,
        "total_executions": total_executions,
        "completed_executions": completed_executions,
        "verified_executions": verified_executions,
        "degraded_executions": degraded_executions,
        "failed_executions": failed_executions,
        "pipeline_integrity_rate": round(integrity_rate, 1),
        "recent_executions": recent_data,
    }


@router.get(
    "/{scenario_id}",
    response_model=SecurityScenarioResponse,
    summary="Get Security Scenario Details",
)
def get_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_READ)),
):
    """Returns scenario details by ID or scenario key."""
    scenario = SecurityScenarioOrchestrationService.get_scenario(db, scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security scenario '{scenario_id}' not found.",
        )
    return scenario


@router.get(
    "/{scenario_id}/versions",
    response_model=List[SecurityScenarioVersionResponse],
    summary="List Scenario Versions",
)
def list_scenario_versions(
    scenario_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_READ)),
):
    """Lists all versions for a scenario."""
    scenario = SecurityScenarioOrchestrationService.get_scenario(db, scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security scenario '{scenario_id}' not found.",
        )
    return SecurityScenarioOrchestrationService.get_scenario_versions(db, scenario.id)


@router.post(
    "/{scenario_id}/versions",
    response_model=SecurityScenarioVersionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Scenario Version",
)
def create_scenario_version(
    scenario_id: str,
    request: SecurityScenarioVersionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_VERSION_MANAGE)),
):
    """Creates a new immutable version of a scenario."""
    scenario = SecurityScenarioOrchestrationService.get_scenario(db, scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security scenario '{scenario_id}' not found.",
        )
    try:
        return SecurityScenarioOrchestrationService.create_scenario_version(
            db=db,
            scenario_id=scenario.id,
            definition_json=request.scenario_definition_json,
            expected_stages=request.expected_stage_sequence_json,
            expected_outcomes=request.expected_outcomes_json,
            deterministic_seed=request.deterministic_seed,
            created_by_user_id=current_user.username,
            set_active=(request.status.value == "ACTIVE"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/{scenario_id}/execute",
    response_model=ScenarioExecutionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start Scenario Execution",
)
def execute_scenario(
    scenario_id: str,
    request: Optional[ScenarioExecutionCreateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_EXECUTE)),
):
    """
    Initializes and executes all 20 canonical stages for a scenario.
    Binds cross-domain artifacts and seals verification in the Governance Ledger.
    """
    scenario = SecurityScenarioOrchestrationService.get_scenario(db, scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security scenario '{scenario_id}' not found.",
        )

    mode = request.execution_mode.value if request else "CONTROLLED_DEMO"
    version_id = request.version_id if request else None
    seed_override = request.deterministic_seed_override if request else None
    notes = request.notes if request else ""

    try:
        execution = SecurityScenarioOrchestrationService.create_execution(
            db=db,
            scenario_id_or_key=scenario.id,
            initiated_by_user_id=current_user.username,
            version_id=version_id,
            execution_mode=mode,
            deterministic_seed_override=seed_override,
            notes=notes,
        )

        # Run all stages
        completed_exec = SecurityScenarioOrchestrationService.execute_all_stages(
            db=db,
            execution_id=execution.id,
            actor_id=str(current_user.id),
            actor_username=current_user.username,
        )
        return completed_exec

    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/executions/{execution_id}",
    response_model=ScenarioExecutionResponse,
    summary="Get Scenario Execution Details",
)
def get_execution(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_READ)),
):
    """Returns execution details with stages and bindings."""
    execution = SecurityScenarioOrchestrationService.get_execution(db, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario execution '{execution_id}' not found.",
        )
    return execution


@router.get(
    "/executions/{execution_id}/timeline",
    response_model=List[Dict[str, Any]],
    summary="Get Chronological Stage Timeline",
)
def get_execution_timeline(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_READ)),
):
    """Returns chronological stage timeline for an execution."""
    execution = SecurityScenarioOrchestrationService.get_execution(db, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario execution '{execution_id}' not found.",
        )
    return SecurityScenarioOrchestrationService.get_execution_timeline(db, execution.id)


@router.get(
    "/executions/{execution_id}/artifacts",
    response_model=List[ScenarioArtifactBindingResponse],
    summary="Get Scenario Artifact Bindings",
)
def get_execution_artifacts(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_READ)),
):
    """Returns artifact bindings for an execution."""
    execution = SecurityScenarioOrchestrationService.get_execution(db, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario execution '{execution_id}' not found.",
        )
    return ScenarioArtifactBindingService.get_execution_artifacts(db, execution.id)


@router.post(
    "/executions/{execution_id}/verify",
    response_model=ScenarioVerificationResponse,
    summary="Perform End-to-End Scenario Verification",
)
def verify_execution(
    execution_id: str,
    request: Optional[ScenarioVerifyRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_VERIFY)),
):
    """
    Executes end-to-end structural and cryptographic verification of an execution.
    """
    execution = SecurityScenarioOrchestrationService.get_execution(db, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario execution '{execution_id}' not found.",
        )

    check_ledger = request.check_ledger if request else True
    check_merkle = request.check_merkle if request else True

    return SecurityScenarioVerificationService.verify_execution(
        db=db,
        execution_id=execution.id,
        verified_by_user_id=current_user.username,
        check_ledger=check_ledger,
        check_merkle=check_merkle,
    )


@router.get(
    "/executions/{execution_id}/verification",
    response_model=ScenarioVerificationResponse,
    summary="Get Verification Result",
)
def get_verification_result(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_READ)),
):
    """Returns existing verification result."""
    verif = SecurityScenarioVerificationService.get_verification_result(db, execution_id)
    if not verif:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Verification result for execution '{execution_id}' not found.",
        )
    return verif


@router.post(
    "/executions/{execution_id}/replay",
    response_model=ScenarioReplayResponse,
    summary="Replay Scenario Execution",
)
def replay_execution(
    execution_id: str,
    request: Optional[ScenarioReplayRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_REPLAY)),
):
    """
    Replays an execution (EVIDENCE_REPLAY or CONTROLLED_REEXECUTION)
    and compares against the original immutable run.
    """
    execution = SecurityScenarioOrchestrationService.get_execution(db, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario execution '{execution_id}' not found.",
        )

    mode = request.execution_mode.value if request else "HISTORICAL_REPLAY"
    verify_orig = request.verify_against_original if request else True

    try:
        return SecurityScenarioReplayService.replay_execution(
            db=db,
            original_execution_id=execution.id,
            replay_mode=mode,
            actor_id=str(current_user.id),
            actor_username=current_user.username,
            verify_against_original=verify_orig,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/executions/{execution_id}/provenance",
    response_model=List[ScenarioProvenanceNode],
    summary="Get 21-Stage Provenance Lineage",
)
def get_scenario_provenance(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_PROVENANCE_READ)),
):
    """Returns 21-stage cross-domain cryptographic provenance lineage."""
    execution = SecurityScenarioOrchestrationService.get_execution(db, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario execution '{execution_id}' not found.",
        )
    return SecurityScenarioProvenanceService.trace_scenario_provenance(db, execution.id)


@router.get(
    "/executions/{execution_id}/executive-impact",
    response_model=ScenarioExecutiveImpactResponse,
    summary="Get Executive Posture Impact",
)
def get_scenario_executive_impact(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SCENARIO_READ)),
):
    """Returns pre vs post posture impact calculation."""
    impact = ScenarioExecutiveImpactService.get_executive_impact(db, execution_id)
    if not impact:
        # Compute if not already computed
        impact = ScenarioExecutiveImpactService.calculate_impact(db, execution_id)
    return impact
