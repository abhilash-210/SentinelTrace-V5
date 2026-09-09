"""
routers/auth.py
---------------
Authentication and Identity Context REST API endpoints.

Sprint 4A — Identity & Role-Based Access Control (RBAC).
Provides:
- POST /api/v1/auth/login -> Issues signed JWT access token upon credential verification
- GET  /api/v1/auth/me    -> Returns authenticated identity context and granted permissions
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.rbac import get_permissions_for_role
from app.core.security import create_access_token
from app.database import get_db
from app.models.user import User
from app.schemas.user import AuthMeResponse, LoginRequest, TokenResponse, UserResponse
from app.services.user_service import UserService

logger = logging.getLogger("sentinel.routers.auth")

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication & Identity"])


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="User Login & JWT Token Generation",
    description="Authenticates user credentials (username/email + password) and issues a signed JWT access token.",
    responses={
        200: {"description": "Authentication successful, token issued"},
        401: {"description": "Invalid credentials or deactivated account"},
    },
)
def login(
    request: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticates credentials and issues signed JWT bearer token."""
    # Ensure demo seed users exist
    UserService.seed_demo_users(db)

    user = UserService.authenticate_user(
        db,
        username_or_email=request.username,
        password=request.password,
    )
    if not user:
        logger.warning(f"Failed login attempt for identifier: '{request.username}'")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Build token payload with user context
    token_claims = {
        "sub": user.user_id,
        "username": user.username,
        "role": user.role,
        "email": user.email,
    }
    access_token = create_access_token(data=token_claims)
    permissions = get_permissions_for_role(user.role)

    logger.info(f"User '{user.username}' successfully authenticated with role '{user.role}'")

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
        permissions=permissions,
    )


@router.get(
    "/me",
    response_model=AuthMeResponse,
    summary="Get Authenticated User Profile",
    description="Returns the currently authenticated user identity and granted RBAC permissions.",
    responses={
        200: {"description": "Current user context"},
        401: {"description": "Unauthorized / Token missing or invalid"},
    },
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> AuthMeResponse:
    """Returns active user identity and permission list."""
    permissions = get_permissions_for_role(current_user.role)
    return AuthMeResponse(
        user=UserResponse.model_validate(current_user),
        permissions=permissions,
    )
