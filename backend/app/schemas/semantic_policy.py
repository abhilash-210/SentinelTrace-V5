"""
schemas/semantic_policy.py
--------------------------
Pydantic schemas for Semantic Policy Registry, Rules, and Protected Semantic Fields.

Sprint 3A — Semantic Policy Registry & Backend Management.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class SemanticPolicyRuleBase(BaseModel):
    """Base schema for a semantic policy mapping rule."""

    source_field: str = Field(..., description="Raw source field name (e.g. 'action')")
    source_value: str = Field(..., description="Raw vendor value (e.g. 'PERMIT')")
    canonical_field: str = Field(..., description="Target canonical field name (e.g. 'action.result')")
    canonical_value: str = Field(..., description="Mapped canonical value (e.g. 'ALLOWED')")
    equivalence_classification: str = Field(
        default="EQUIVALENT",
        description="Equivalence level: 'EQUIVALENT', 'COMPATIBLE', 'AMBIGUOUS', 'INCOMPATIBLE'",
    )
    risk_level: str = Field(
        default="LOW",
        description="Risk rating: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )
    description: Optional[str] = Field(
        default=None,
        description="Rule rationale and edge-case documentation",
    )


class SemanticPolicyRuleCreate(SemanticPolicyRuleBase):
    """Schema for creating a rule within a policy."""

    rule_id: Optional[str] = Field(
        default=None,
        description="Optional custom rule identifier",
    )


class SemanticPolicyRuleResponse(SemanticPolicyRuleBase):
    """Response schema for a single semantic policy rule."""

    id: int
    rule_id: str
    policy_id: str
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class SemanticPolicySummaryResponse(BaseModel):
    """Summary representation of a Semantic Policy."""

    id: int
    policy_id: str = Field(..., description="Unique policy identifier")
    policy_name: str = Field(..., description="Human-readable policy title")
    vendor_name: str = Field(..., description="Originating vendor or product family")
    source_profile_id: str = Field(..., description="Associated structural Source Profile identifier")
    version: int = Field(default=1, description="Policy version number")
    status: str = Field(..., description="Lifecycle state: 'DRAFT', 'ACTIVE', 'SUPERSEDED', 'RETIRED'")
    description: Optional[str] = Field(default=None, description="Policy documentation")
    supersedes_policy_id: Optional[str] = Field(default=None, description="Superseded policy identifier")
    rule_count: int = Field(default=0, description="Total number of rules configured under this policy")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class SemanticPolicyDetailResponse(SemanticPolicySummaryResponse):
    """Detailed representation of a Semantic Policy including all rules."""

    rules: List[SemanticPolicyRuleResponse] = Field(default_factory=list, description="All policy-scoped rules")

    model_config = ConfigDict(from_attributes=True)


class SemanticPolicyCreateRequest(BaseModel):
    """Request payload for creating a new semantic policy. Defaults to DRAFT."""

    policy_id: Optional[str] = Field(
        default=None,
        description="Optional explicit policy identifier (e.g. 'spol_custom_firewall_v1')",
    )
    policy_name: str = Field(..., description="Human-readable policy title")
    vendor_name: str = Field(..., description="Originating vendor or product family")
    source_profile_id: str = Field(..., description="Associated structural Source Profile identifier")
    version: int = Field(default=1, description="Policy version number")
    status: str = Field(
        default="DRAFT",
        description="Lifecycle status. Note: New policies always initialize to 'DRAFT'",
    )
    description: Optional[str] = Field(default=None, description="Technical rationale for policy")
    supersedes_policy_id: Optional[str] = Field(default=None, description="Identifier of policy being replaced")
    rules: Optional[List[SemanticPolicyRuleCreate]] = Field(
        default_factory=list,
        description="Initial set of semantic rules to attach to the policy",
    )


class ProtectedSemanticFieldResponse(BaseModel):
    """Response schema for a protected security-sensitive semantic field."""

    id: int
    field_name: str = Field(..., description="Canonical field path (e.g. 'action.result')")
    criticality: str = Field(..., description="Criticality rating: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'")
    description: str = Field(..., description="Security significance documentation")
    is_protected: bool = Field(default=True, description="Protection flag")
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
