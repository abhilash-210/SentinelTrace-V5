"""
services/source_profile_service.py
----------------------------------
Manages the Source Profile onboarding lifecycle and testing.
Sprint 6 — Source Profile Onboarding & Approvals.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from datetime import datetime, timezone
import json

from app.models.source_profile import SourceProfile, SourceProfileApprovalRequest
from app.schemas.source_profile import (
    SourceProfileCreateRequest,
    SourceProfileUpdateRequest,
    SourceProfileTestRequest,
    SourceProfileTestResponse,
)
from app.parsers import PARSER_REGISTRY
from app.services.validation_service import ValidationService
from app.models.normalized_event import NormalizedEvent
import uuid

logger = logging.getLogger(__name__)


class SourceProfileApprovalForbiddenError(Exception):
    pass


class SourceProfileService:
    @staticmethod
    def create_draft_profile(
        db: Session, request: SourceProfileCreateRequest, user_id: str
    ) -> SourceProfile:
        profile_id = f"sp_{uuid.uuid4().hex[:12]}"
        
        profile = SourceProfile(
            source_profile_id=profile_id,
            profile_name=request.profile_name,
            source_type=request.source_type,
            supported_format=request.supported_format,
            parser_type=request.parser_type,
            configuration=request.configuration,
            status="DRAFT",
            is_active=False,
            created_by=user_id,
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
        return profile

    @staticmethod
    def list_profiles(
        db: Session, status: Optional[str] = None, limit: int = 50, offset: int = 0
    ) -> Tuple[List[SourceProfile], int]:
        stmt = select(SourceProfile)
        count_stmt = select(func.count()).select_from(SourceProfile)
        
        if status:
            stmt = stmt.where(SourceProfile.status == status.upper())
            count_stmt = count_stmt.where(SourceProfile.status == status.upper())
            
        total = db.execute(count_stmt).scalar_one()
        query = stmt.order_by(SourceProfile.created_at.desc()).limit(limit).offset(offset)
        items = list(db.execute(query).scalars().all())
        return items, total

    @staticmethod
    def get_profile(db: Session, source_profile_id: str) -> Optional[SourceProfile]:
        return db.execute(
            select(SourceProfile).where(SourceProfile.source_profile_id == source_profile_id)
        ).scalar_one_or_none()

    @staticmethod
    def update_draft_profile(
        db: Session, source_profile_id: str, request: SourceProfileUpdateRequest
    ) -> Optional[SourceProfile]:
        profile = SourceProfileService.get_profile(db, source_profile_id)
        if not profile or profile.status != "DRAFT":
            return None
            
        if request.profile_name:
            profile.profile_name = request.profile_name
        if request.source_type:
            profile.source_type = request.source_type
        if request.supported_format:
            profile.supported_format = request.supported_format
        if request.parser_type:
            profile.parser_type = request.parser_type
        if request.configuration is not None:
            profile.configuration = request.configuration
            
        db.commit()
        db.refresh(profile)
        return profile

    @staticmethod
    def test_profile(request: SourceProfileTestRequest) -> SourceProfileTestResponse:
        parser = PARSER_REGISTRY.get(request.parser_type)
        if not parser:
            return SourceProfileTestResponse(
                success=False, error_message=f"Parser {request.parser_type} not found."
            )
            
        try:
            # We pass configuration to the parser via metadata_ for simulation
            metadata_ = {"profile_configuration": request.configuration}
            parse_result = parser.parse(request.sample_event, metadata_)
            if not parse_result.get("success"):
                return SourceProfileTestResponse(
                    success=False,
                    error_message=parse_result.get("error", "Parse failed"),
                )
                
            fields = parse_result.get("fields", {})
            mapped_keys = {
                "action", "src_ip", "src_port", "dst_ip", "dst_port",
                "protocol", "severity", "user_name", "hostname",
                "process_name", "process_id"
            }
            # Simulate mappings if configuration specifies them
            mappings = request.configuration.get("field_mappings", {})
            mapped_fields = {}
            for target, source in mappings.items():
                if source in fields:
                    mapped_fields[target] = fields[source]
                    
            # Overwrite fields with mapped values
            for k, v in mapped_fields.items():
                fields[k] = v
                
            unmapped_data = {k: v for k, v in fields.items() if k not in mapped_keys}
            
            normalized = NormalizedEvent(
                normalized_event_id="test_id",
                original_event_id="test_raw_id",
                class_uid=4001,
                class_name="Network Activity",
                activity_id=1,
                activity_name="Network Traffic",
                event_time=parse_result.get("timestamp") or datetime.now(timezone.utc),
                source_name="test_source",
                source_type="test_type",
                action=fields.get("action"),
                src_ip=fields.get("src_ip"),
                src_port=fields.get("src_port"),
                dst_ip=fields.get("dst_ip"),
                dst_port=fields.get("dst_port"),
                protocol=fields.get("protocol"),
                severity=fields.get("severity"),
                user_name=fields.get("user_name"),
                hostname=fields.get("hostname"),
                process_name=fields.get("process_name"),
                process_id=fields.get("process_id"),
                raw_data=fields,
                unmapped_data=unmapped_data,
                normalization_status="NORMALIZED",
            )
            
            validation_result = ValidationService.validate_normalized_event(normalized)
            
            return SourceProfileTestResponse(
                success=validation_result["valid"],
                mapped_fields={k: v for k, v in fields.items() if k in mapped_keys},
                unmapped_fields=unmapped_data,
                validation_result=validation_result,
                normalized_preview=normalized.to_dict(),
            )
        except Exception as e:
            return SourceProfileTestResponse(success=False, error_message=str(e))

    @staticmethod
    def submit_for_approval(db: Session, source_profile_id: str, user_id: str) -> Tuple[SourceProfile, SourceProfileApprovalRequest]:
        profile = SourceProfileService.get_profile(db, source_profile_id)
        if not profile or profile.status != "DRAFT":
            raise ValueError("Only DRAFT profiles can be submitted for approval.")
            
        profile.status = "PENDING_APPROVAL"
        
        approval = SourceProfileApprovalRequest(
            source_profile_id=source_profile_id,
            requested_by_user_id=user_id,
            status="PENDING",
        )
        db.add(approval)
        db.commit()
        db.refresh(profile)
        db.refresh(approval)
        
        return profile, approval
        
    @staticmethod
    def approve_profile(db: Session, approval_id: str, reviewer_id: str, comment: str) -> SourceProfileApprovalRequest:
        approval = db.execute(
            select(SourceProfileApprovalRequest).where(SourceProfileApprovalRequest.approval_id == approval_id)
        ).scalar_one_or_none()
        
        if not approval or approval.status != "PENDING":
            raise ValueError("Approval request not found or not pending.")
            
        if approval.requested_by_user_id == reviewer_id:
            raise SourceProfileApprovalForbiddenError("Author cannot approve their own profile.")
            
        approval.status = "APPROVED"
        approval.reviewed_by_user_id = reviewer_id
        approval.reviewed_at = datetime.now(timezone.utc)
        approval.review_comment = comment
        
        profile = SourceProfileService.get_profile(db, approval.source_profile_id)
        profile.status = "APPROVED"
        profile.approved_by = reviewer_id
        
        db.commit()
        db.refresh(approval)
        return approval

    @staticmethod
    def activate_profile(db: Session, source_profile_id: str) -> Optional[SourceProfile]:
        profile = SourceProfileService.get_profile(db, source_profile_id)
        if not profile or profile.status != "APPROVED":
            raise ValueError("Only APPROVED profiles can be activated.")
            
        profile.status = "ACTIVE"
        profile.is_active = True
        db.commit()
        db.refresh(profile)
        return profile
        
    @staticmethod
    def deactivate_profile(db: Session, source_profile_id: str) -> Optional[SourceProfile]:
        profile = SourceProfileService.get_profile(db, source_profile_id)
        if not profile:
            raise ValueError("Profile not found.")
            
        profile.status = "INACTIVE"
        profile.is_active = False
        db.commit()
        db.refresh(profile)
        return profile
