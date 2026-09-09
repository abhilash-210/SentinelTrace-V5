"""
core/auth.py
------------
FastAPI dependencies for JWT Authentication, Identity Context, and RBAC Authorization.

Sprint 4A — Identity & Role-Based Access Control (RBAC).
"""

import logging
from typing import Callable, List, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.rbac import Role, has_permission
from app.core.security import decode_access_token
from app.database import get_db
from app.models.user import User
from app.services.user_service import UserService

logger = logging.getLogger("sentinel.core.auth")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Dependency that extracts and verifies the JWT token from the Authorization header.
    Returns the authenticated User entity.
    Raises 401 UNAUTHORIZED if token is missing, expired, invalid, or user is inactive.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(token)
        user_id: Optional[str] = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token claims: subject missing.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    # Ensure demo users are seeded if empty
    UserService.seed_demo_users(db)

    user = UserService.get_user_by_id(db, user_id)
    if not user:
        # Fallback to username lookup if sub stored username
        user = UserService.get_user_by_username_or_email(db, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User identity associated with token not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_permission(permission: str) -> Callable[[User], User]:
    """
    Factory creating a FastAPI dependency that verifies the authenticated user's role
    possesses the requested system permission according to the RBAC matrix.
    Raises 403 FORBIDDEN if permission is denied.
    """
    def _permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if not has_permission(current_user.role, permission):
            logger.warning(
                f"Access denied: User '{current_user.username}' with role '{current_user.role}' "
                f"lacks permission '{permission}'"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"ACCESS RESTRICTED: Role '{current_user.role}' lacks required permission '{permission}'.",
            )
        return current_user

    return _permission_checker


def require_any_permission(permissions: List[str]) -> Callable[[User], User]:
    """
    Factory creating a FastAPI dependency that checks if the authenticated user
    possesses at least one of the listed permissions.
    """
    def _any_permission_checker(current_user: User = Depends(get_current_user)) -> User:
        for perm in permissions:
            if has_permission(current_user.role, perm):
                return current_user
        logger.warning(
            f"Access denied: User '{current_user.username}' with role '{current_user.role}' "
            f"lacks any of required permissions {permissions}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"ACCESS RESTRICTED: Role '{current_user.role}' lacks any of required permissions {permissions}.",
        )
    return _any_permission_checker


def require_role(allowed_roles: List[str]) -> Callable[[User], User]:
    """
    Factory creating a FastAPI dependency that restricts access to specific explicit roles.
    Raises 403 FORBIDDEN if user role is not in allowed_roles.
    """
    def _role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"ACCESS RESTRICTED: Requires one of roles: {allowed_roles}. Current role: '{current_user.role}'.",
            )
        return current_user

    return _role_checker
