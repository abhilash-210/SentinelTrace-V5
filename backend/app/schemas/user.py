"""
schemas/user.py
---------------
Pydantic schemas for User Identity, Authentication, and RBAC Management.

Sprint 4A — Identity & Role-Based Access Control (RBAC).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserBase(BaseModel):
    """Base schema for user identity."""
    username: str = Field(..., min_length=3, max_length=64, description="Unique login username")
    email: EmailStr = Field(..., description="Unique email address")
    full_name: str = Field(..., min_length=1, max_length=255, description="Full display name")
    role: str = Field(default="VIEWER", description="Assigned RBAC role")
    is_active: bool = Field(default=True, description="Account active status")


class UserCreate(UserBase):
    """Payload for creating a new user."""
    password: str = Field(..., min_length=8, description="Plaintext password (hashed before storage)")


class UserUpdate(BaseModel):
    """Payload for updating user profile (Admin only)."""
    full_name: Optional[str] = Field(None, min_length=1, max_length=255)
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=8)


class UserResponse(UserBase):
    """Public user identity schema (password_hash is strictly omitted)."""
    id: int
    user_id: str = Field(..., description="Public user identifier (e.g. 'usr_12345678')")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class UserListResponse(BaseModel):
    """Paginated list of users."""
    total: int
    items: List[UserResponse]


# ── Authentication Schemas ─────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    """Login credentials payload."""
    username: str = Field(..., description="Username or email address")
    password: str = Field(..., description="Plain-text password")


class TokenResponse(BaseModel):
    """Authentication token response payload."""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    permissions: List[str] = Field(default_factory=list, description="List of granted permissions")


class AuthMeResponse(BaseModel):
    """Authenticated user context representation."""
    user: UserResponse
    permissions: List[str] = Field(default_factory=list)


class AccessRestrictedResponse(BaseModel):
    """Structured response for 403 Forbidden Access Restricted errors."""
    detail: str
    current_role: str
    required_permission: str
