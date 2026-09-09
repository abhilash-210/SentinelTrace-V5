"""
routers/user.py
---------------
User Management REST API endpoints (Admin only).

Sprint 4A — Identity & Role-Based Access Control (RBAC).
Provides:
- GET   /api/v1/users           -> List all users (Admin/Auditor only)
- GET   /api/v1/users/{user_id} -> Get user details (Admin/Auditor only)
- POST  /api/v1/users           -> Create new user (Admin only)
- PATCH /api/v1/users/{user_id} -> Update user details & role (Admin only)
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import require_permission
from app.database import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserListResponse, UserResponse, UserUpdate
from app.services.user_service import UserService

logger = logging.getLogger("sentinel.routers.user")

router = APIRouter(prefix="/api/v1/users", tags=["User & Identity Governance"])


@router.get(
    "",
    response_model=UserListResponse,
    summary="List System Users",
    description="Retrieves list of all registered users with role and status metadata. Requires `USER_READ` or `USER_MANAGE` permission.",
    responses={
        200: {"description": "List of users"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden - Insufficient permission"},
    },
)
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(require_permission("USER_READ")),
    db: Session = Depends(get_db),
) -> UserListResponse:
    """List system users with pagination."""
    UserService.seed_demo_users(db)
    users, total = UserService.list_users(db, skip=skip, limit=limit)
    return UserListResponse(
        total=total,
        items=[UserResponse.model_validate(u) for u in users],
    )


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get User Identity by ID",
    description="Retrieves a single user identity record. Requires `USER_READ` or `USER_MANAGE` permission.",
    responses={
        200: {"description": "User details"},
        404: {"description": "User not found"},
    },
)
def get_user(
    user_id: str,
    current_user: User = Depends(require_permission("USER_READ")),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Fetch single user identity."""
    UserService.seed_demo_users(db)
    user = UserService.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found.",
        )
    return UserResponse.model_validate(user)


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create New User (Admin Only)",
    description="Registers a new system user identity and assigns an RBAC role. Requires `USER_MANAGE` permission (Admin only).",
    responses={
        201: {"description": "User created successfully"},
        400: {"description": "Validation error or duplicate user"},
        403: {"description": "Forbidden - Admin privilege required"},
    },
)
def create_user(
    request: UserCreate,
    current_user: User = Depends(require_permission("USER_MANAGE")),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Creates a new user record with securely hashed password."""
    try:
        new_user = UserService.create_user(db, request)
        logger.info(f"User '{new_user.username}' created by admin '{current_user.username}'")
        return UserResponse.model_validate(new_user)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update User Profile & Role (Admin Only)",
    description="Modifies user profile, active state, or RBAC role. Requires `USER_MANAGE` permission (Admin only).",
    responses={
        200: {"description": "User updated successfully"},
        400: {"description": "Validation error"},
        404: {"description": "User not found"},
    },
)
def update_user(
    user_id: str,
    request: UserUpdate,
    current_user: User = Depends(require_permission("USER_MANAGE")),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Updates user attributes and role assignment."""
    try:
        updated = UserService.update_user(db, user_id, request)
        logger.info(f"User '{updated.username}' updated by admin '{current_user.username}'")
        return UserResponse.model_validate(updated)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
