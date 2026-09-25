"""
routers/source_profiles.py
--------------------------
API routes for Source Profiles.
Sprint 6 — Source Profile Onboarding & Approvals.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.routers.auth import get_current_user
from app.models.user import User
from app.schemas.source_profile import (
    SourceProfileResponse,
    SourceProfileListResponse,
    SourceProfileCreateRequest,
    SourceProfileUpdateRequest,
    SourceProfileTestRequest,
    SourceProfileTestResponse,
    SourceProfileApprovalResponse,
    SourceProfileApprovalSubmitResponse,
)
from app.services.source_profile_service import SourceProfileService, SourceProfileApprovalForbiddenError

router = APIRouter(prefix="/api/v1/source-profiles", tags=["Source Profiles"])


@router.post("", response_model=SourceProfileResponse)
def create_draft_profile(
    request: SourceProfileCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return SourceProfileService.create_draft_profile(db, request, current_user.user_id)


@router.get("", response_model=SourceProfileListResponse)
def list_profiles(
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items, total = SourceProfileService.list_profiles(db, status=status, limit=limit, offset=offset)
    return SourceProfileListResponse(items=[SourceProfileResponse.model_validate(item) for item in items], total=total)


@router.get("/{source_profile_id}", response_model=SourceProfileResponse)
def get_profile(
    source_profile_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    profile = SourceProfileService.get_profile(db, source_profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


@router.put("/{source_profile_id}", response_model=SourceProfileResponse)
def update_draft_profile(
    source_profile_id: str,
    request: SourceProfileUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    profile = SourceProfileService.update_draft_profile(db, source_profile_id, request)
    if not profile:
        raise HTTPException(status_code=400, detail="Profile not found or not in DRAFT status")
    return profile


@router.post("/test", response_model=SourceProfileTestResponse)
def test_profile(
    request: SourceProfileTestRequest,
    current_user: User = Depends(get_current_user),
):
    return SourceProfileService.test_profile(request)


@router.post("/{source_profile_id}/submit", response_model=SourceProfileApprovalSubmitResponse)
def submit_for_approval(
    source_profile_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        profile, approval = SourceProfileService.submit_for_approval(db, source_profile_id, current_user.user_id)
        return SourceProfileApprovalSubmitResponse(
            approval_id=approval.approval_id,
            approval_status=approval.status,
            requested_at=approval.requested_at,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/approvals/{approval_id}/approve", response_model=SourceProfileApprovalResponse)
def approve_profile(
    approval_id: str,
    comment: str = "Looks good.",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        approval = SourceProfileService.approve_profile(db, approval_id, current_user.user_id, comment)
        return approval
    except SourceProfileApprovalForbiddenError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{source_profile_id}/activate", response_model=SourceProfileResponse)
def activate_profile(
    source_profile_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return SourceProfileService.activate_profile(db, source_profile_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{source_profile_id}/deactivate", response_model=SourceProfileResponse)
def deactivate_profile(
    source_profile_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return SourceProfileService.deactivate_profile(db, source_profile_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
