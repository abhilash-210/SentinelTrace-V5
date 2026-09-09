"""
schemas/detection_rule.py
--------------------------
Pydantic validation schemas for the Detection Rule Registry &
Canonical Field Dependency Mapping.

Sprint 6A — Detection Rule Registry & Canonical Field Dependency Mapping.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


# ── Dependency Schemas ─────────────────────────────────────────────────────────

class DetectionRuleDependencyBase(BaseModel):
    """Base schema for a detection rule canonical field dependency."""
    canonical_field: str = Field(..., min_length=1, max_length=100, description="Canonical field name this rule depends on")
    dependency_type: str = Field("REQUIRED", description="Dependency classification: REQUIRED, OPTIONAL, ENRICHMENT")
    description: Optional[str] = Field(None, description="Rationale for dependency")


class DetectionRuleDependencyCreate(DetectionRuleDependencyBase):
    """Schema for creating a new dependency edge."""
    pass


class DetectionRuleDependencyResponse(DetectionRuleDependencyBase):
    """Response schema for a detection rule dependency."""
    dependency_id: str
    rule_id: str
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── Detection Rule Schemas ─────────────────────────────────────────────────────

class DetectionRuleCreateRequest(BaseModel):
    """Schema for creating a new detection rule (always DRAFT)."""
    rule_name: str = Field(..., min_length=1, max_length=255, description="Human-readable detection rule title")
    vendor_name: str = Field(..., min_length=1, max_length=255, description="Vendor scope")
    description: Optional[str] = Field(None, description="Technical description")
    severity: str = Field("MEDIUM", description="Rule severity: LOW, MEDIUM, HIGH, CRITICAL")
    mitre_tactic: Optional[str] = Field(None, description="MITRE ATT&CK tactic reference")
    mitre_technique: Optional[str] = Field(None, description="MITRE ATT&CK technique reference")
    dependencies: Optional[List[DetectionRuleDependencyCreate]] = Field(
        default_factory=list, description="Canonical field dependencies declared at creation"
    )


class DetectionRuleSummaryResponse(BaseModel):
    """Summary response schema for detection rule listings."""
    rule_id: str
    rule_name: str
    vendor_name: str
    severity: str
    status: str
    version: int
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    dependency_count: int = 0
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class DetectionRuleDetailResponse(BaseModel):
    """Detailed response schema including dependencies."""
    rule_id: str
    rule_name: str
    vendor_name: str
    description: Optional[str] = None
    severity: str
    status: str
    version: int
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    created_by: Optional[str] = None
    dependency_count: int = 0
    dependencies: List[DetectionRuleDependencyResponse] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class DetectionRuleListResponse(BaseModel):
    """Paginated list response for detection rules."""
    total: int
    limit: int
    offset: int
    items: List[DetectionRuleSummaryResponse]


# ── Impact Analysis Schema ─────────────────────────────────────────────────────

class FieldImpactEntry(BaseModel):
    """Single entry in field impact analysis results."""
    rule_id: str
    rule_name: str
    vendor_name: str
    severity: str
    status: str
    dependency_type: str


class FieldImpactAnalysisResponse(BaseModel):
    """Response for canonical field impact analysis."""
    canonical_field: str
    total_dependent_rules: int
    impacted_rules: List[FieldImpactEntry]


# ── Dependency Graph Schema ───────────────────────────────────────────────────

class DependencyGraphNode(BaseModel):
    """A node in the dependency graph."""
    id: str
    label: str
    type: str  # "rule" or "field"
    severity: Optional[str] = None
    status: Optional[str] = None


class DependencyGraphEdge(BaseModel):
    """An edge in the dependency graph."""
    source: str
    target: str
    dependency_type: str


class DependencyGraphResponse(BaseModel):
    """Full dependency graph for visualization."""
    nodes: List[DependencyGraphNode]
    edges: List[DependencyGraphEdge]
    total_rules: int
    total_fields: int
