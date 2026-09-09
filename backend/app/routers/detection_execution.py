"""
routers/detection_execution.py
-------------------------------
REST API Router for Real-Time Detection Rule Execution Engine.

Sprint 7A — Real-Time Detection Rule Execution Engine.

Provides:
- POST /api/v1/normalized-events/{normalized_event_id}/run-detections (Run all ACTIVE rules)
- POST /api/v1/detection-rules/{rule_id}/execute/{normalized_event_id} (Run single ACTIVE rule)
- GET  /api/v1/detection-executions (List executions with filters & pagination)
- GET  /api/v1/detection-executions/{execution_id} (Get execution detail)
- GET  /api/v1/detection-executions/{execution_id}/trace (10-stage provenance trace)
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.detection_execution import DetectionExecution
from app.models.user import User
from app.schemas.detection_execution import (
    DetectionExecutionListResponse,
    DetectionExecutionResponse,
    ExecutionProvenanceTraceResponse,
    RunDetectionsForEventResponse,
)
from app.services.detection_execution_service import DetectionExecutionService

logger = logging.getLogger("sentinel.routers.detection_execution")

router = APIRouter(
    prefix="/api/v1",
    tags=["Detection Execution Engine"],
)


@router.post(
    "/normalized-events/{normalized_event_id}/run-detections",
    response_model=RunDetectionsForEventResponse,
    summary="Run All Active Detection Rules Against Event",
    description="Evaluates all currently ACTIVE governed detection rules against a normalized security event.",
)
def run_all_active_detections_for_event(
    normalized_event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_EXECUTE.value)),
):
    """Execute all active detection rules against a normalized event."""
    try:
        res = DetectionExecutionService.execute_active_rules_for_event(db, normalized_event_id)
        return res
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        logger.error("Error executing active detections for event '%s': %s", normalized_event_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Detection execution failed: {str(e)}",
        )


@router.post(
    "/detection-rules/{rule_id}/execute/{normalized_event_id}",
    response_model=DetectionExecutionResponse,
    summary="Execute Single Active Detection Rule Against Event",
    description="Evaluates a specific ACTIVE governed detection rule version against a normalized event.",
)
def execute_single_rule_against_event(
    rule_id: str,
    normalized_event_id: str,
    force_recompute: bool = Query(False, description="Force re-evaluation ignoring idempotency cache"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_EXECUTE.value)),
):
    """Execute a single active detection rule against an event."""
    try:
        exec_record = DetectionExecutionService.execute_rule_against_event(
            db=db,
            rule_id=rule_id,
            normalized_event_id=normalized_event_id,
            force_recompute=force_recompute,
        )
        return exec_record.to_dict()
    except ValueError as e:
        err_msg = str(e)
        if "not found" in err_msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
    except Exception as e:
        logger.error("Error executing rule '%s' on event '%s': %s", rule_id, normalized_event_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rule execution error: {str(e)}",
        )


@router.get(
    "/detection-executions",
    response_model=DetectionExecutionListResponse,
    summary="List Detection Executions",
    description="Query paginated detection execution records with optional status, rule, and match filters.",
)
def list_detection_executions(
    rule_id: Optional[str] = Query(None, description="Filter by detection rule ID"),
    execution_status: Optional[str] = Query(None, description="Filter by status ('MATCH', 'NO_MATCH', 'PARTIAL', 'ERROR')"),
    normalized_event_id: Optional[str] = Query(None, description="Filter by normalized event ID"),
    matched: Optional[bool] = Query(None, description="Filter by match outcome boolean"),
    limit: int = Query(50, ge=1, le=200, description="Items per page"),
    offset: int = Query(0, ge=0, description="Offset"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_EXECUTION_READ.value)),
):
    """List execution records."""
    query = db.query(DetectionExecution)

    if rule_id:
        query = query.filter(DetectionExecution.rule_id == rule_id)
    if execution_status:
        query = query.filter(DetectionExecution.execution_status == execution_status.upper())
    if normalized_event_id:
        query = query.filter(DetectionExecution.normalized_event_id == normalized_event_id)
    if matched is not None:
        query = query.filter(DetectionExecution.matched == matched)

    total = query.count()
    records = (
        query.order_by(DetectionExecution.executed_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "executions": [r.to_dict() for r in records],
    }


@router.get(
    "/detection-executions/{execution_id}",
    response_model=DetectionExecutionResponse,
    summary="Get Detection Execution Detail",
    description="Returns detailed execution record including atomic condition results and explainability statements.",
)
def get_detection_execution_detail(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_EXECUTION_READ.value)),
):
    """Retrieve single execution record."""
    record = (
        db.query(DetectionExecution)
        .filter(DetectionExecution.execution_id == execution_id)
        .first()
    )
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution record '{execution_id}' not found.",
        )
    return record.to_dict()


@router.get(
    "/detection-executions/{execution_id}/trace",
    response_model=ExecutionProvenanceTraceResponse,
    summary="Get 10-Stage Execution Provenance Trace",
    description="Retrieves the full 10-stage end-to-end cryptographic and governance provenance chain.",
)
def get_detection_execution_trace(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_READ.value)),
):
    """Generate 10-stage provenance trace."""
    try:
        trace = DetectionExecutionService.get_execution_trace(db, execution_id)
        return trace
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        logger.error("Error building trace for execution '%s': %s", execution_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Trace retrieval failed: {str(e)}",
        )
