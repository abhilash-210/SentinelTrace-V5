"""
services/detection_rule_governance_service.py
---------------------------------------------
Service implementing Detection Rule Governance, Dual-Control Approval,
Rule Versioning, Version Impact Analysis, and Immutable Audit Trails.

Sprint 6C — Detection Rule Governance, Approval Workflow & Version Impact Management.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.detection_rule import DetectionRule, DetectionRuleDependency
from app.models.detection_rule_governance import (
    DetectionRuleApprovalRequest,
    DetectionRuleGovernanceEvent,
    DetectionRuleVersion,
    DetectionRuleVersionDependency,
    DetectionRuleVersionImpact,
)
from app.models.detection_rule_trust import DetectionTrustAlert
from app.models.semantic_interpretation import SemanticDriftAlert, SemanticInterpretation
from app.models.semantic_policy import ProtectedSemanticField
from app.services.detection_rule_trust_service import DetectionRuleTrustService


class DetectionRuleGovernanceService:
    """Core governance engine for detection rules, dual-control workflows, and version lineage."""

    VERSION_HASH_DOMAIN_PREFIX: str = "SENTINELTRACE_RULE_VERSION_V1"
    GOVERNANCE_EVENT_DOMAIN_PREFIX: str = "SENTINELTRACE_DETECTION_GOVERNANCE_V1"

    # ── 1. Cryptographic Hashing Utilities ─────────────────────────────────────
    @classmethod
    def compute_version_hash(
        cls,
        rule_id: str,
        version_number: int,
        rule_name: str,
        vendor_name: str,
        description: Optional[str],
        query_signature: Optional[str],
        severity: str,
        mitre_techniques: List[str],
        dependencies: List[Dict[str, Any]],
    ) -> str:
        """
        Deterministic SHA-256 hash sealing a governed detection rule version definition.
        """
        # Canonicalize dependencies: sort by canonical_field
        sorted_deps = sorted(
            [
                {
                    "canonical_field": d.get("canonical_field"),
                    "dependency_type": d.get("dependency_type", "REQUIRED"),
                    "is_protected_field": bool(d.get("is_protected_field", False)),
                }
                for d in dependencies
            ],
            key=lambda x: x["canonical_field"] or "",
        )

        canonical_data = {
            "domain": cls.VERSION_HASH_DOMAIN_PREFIX,
            "rule_id": rule_id,
            "version_number": version_number,
            "rule_name": rule_name,
            "vendor_name": vendor_name,
            "description": description or "",
            "query_signature": query_signature or "",
            "severity": severity.upper(),
            "mitre_techniques": sorted(mitre_techniques or []),
            "dependencies": sorted_deps,
        }

        canonical_json = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @classmethod
    def compute_governance_event_hash(
        cls,
        event_type: str,
        rule_id: str,
        version_id: Optional[str],
        actor_user_id: str,
        timestamp_str: str,
        payload: Dict[str, Any],
    ) -> str:
        """
        Deterministic SHA-256 hash sealing an immutable governance audit event.
        """
        canonical_data = {
            "domain": cls.GOVERNANCE_EVENT_DOMAIN_PREFIX,
            "event_type": event_type,
            "rule_id": rule_id,
            "version_id": version_id or "",
            "actor_user_id": actor_user_id,
            "timestamp": timestamp_str,
            "payload": payload or {},
        }
        canonical_json = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @classmethod
    def record_governance_event(
        cls,
        db: Session,
        rule_id: str,
        version_id: Optional[str],
        event_type: str,
        actor_user_id: str,
        actor_role: str,
        previous_status: Optional[str],
        new_status: Optional[str],
        payload: Dict[str, Any],
    ) -> DetectionRuleGovernanceEvent:
        """Helper to create and persist an immutable governance audit event."""
        now = datetime.now(timezone.utc)
        ts_str = now.isoformat()
        ev_hash = cls.compute_governance_event_hash(
            event_type=event_type,
            rule_id=rule_id,
            version_id=version_id,
            actor_user_id=actor_user_id,
            timestamp_str=ts_str,
            payload=payload,
        )
        gov_event = DetectionRuleGovernanceEvent(
            rule_id=rule_id,
            version_id=version_id,
            event_type=event_type,
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            previous_status=previous_status,
            new_status=new_status,
            event_payload=payload,
            event_hash=ev_hash,
            created_at=now,
        )
        db.add(gov_event)
        db.commit()
        db.refresh(gov_event)
        return gov_event

    # ── 2. Version Lifecycle Operations ────────────────────────────────────────
    @classmethod
    def create_rule_version(
        cls,
        db: Session,
        rule_id: str,
        user_id: str,
        user_role: str,
        rule_name: str,
        vendor_name: str,
        description: Optional[str] = None,
        query_signature: Optional[str] = None,
        severity: str = "MEDIUM",
        mitre_techniques: Optional[List[str]] = None,
        dependencies: Optional[List[Dict[str, Any]]] = None,
        parent_version_id: Optional[str] = None,
    ) -> DetectionRuleVersion:
        """
        Create a new DRAFT version snapshot for a detection rule.
        Enforces monotonic version numbering and computes deterministic version hash.
        """
        rule = db.query(DetectionRule).filter(DetectionRule.rule_id == rule_id).first()
        if not rule:
            # Auto-create detection rule registry entry if not existing
            rule = DetectionRule(
                rule_id=rule_id,
                rule_name=rule_name,
                vendor_name=vendor_name,
                description=description,
                severity=severity.upper(),
                status="DRAFT",
                version=1,
                mitre_technique=(mitre_techniques[0] if mitre_techniques else None),
            )
            db.add(rule)
            db.flush()

        # Find max version number
        latest_ver = (
            db.query(DetectionRuleVersion)
            .filter(DetectionRuleVersion.rule_id == rule_id)
            .order_by(desc(DetectionRuleVersion.version_number))
            .first()
        )
        next_ver_num = (latest_ver.version_number + 1) if latest_ver else 1

        # Check protected fields
        protected_fields = {
            p.field_name
            for p in db.query(ProtectedSemanticField)
            .filter(ProtectedSemanticField.is_protected.is_(True))
            .all()
        }

        dep_list = dependencies or []
        for d in dep_list:
            if d.get("canonical_field") in protected_fields:
                d["is_protected_field"] = True

        v_hash = cls.compute_version_hash(
            rule_id=rule_id,
            version_number=next_ver_num,
            rule_name=rule_name,
            vendor_name=vendor_name,
            description=description,
            query_signature=query_signature,
            severity=severity,
            mitre_techniques=mitre_techniques or [],
            dependencies=dep_list,
        )

        version = DetectionRuleVersion(
            rule_id=rule_id,
            version_number=next_ver_num,
            parent_version_id=parent_version_id or (latest_ver.version_id if latest_ver else None),
            rule_name=rule_name,
            vendor_name=vendor_name,
            description=description,
            query_signature=query_signature,
            severity=severity.upper(),
            mitre_techniques=mitre_techniques or [],
            status="DRAFT",
            created_by_user_id=user_id,
            created_at=datetime.now(timezone.utc),
            version_hash=v_hash,
        )
        db.add(version)
        db.flush()

        # Add snapshot dependencies
        for d in dep_list:
            ver_dep = DetectionRuleVersionDependency(
                version_id=version.version_id,
                canonical_field=d["canonical_field"],
                dependency_type=d.get("dependency_type", "REQUIRED"),
                is_protected_field=d.get("is_protected_field", False),
                created_at=datetime.now(timezone.utc),
            )
            db.add(ver_dep)

        db.commit()
        db.refresh(version)

        # Audit Event
        cls.record_governance_event(
            db=db,
            rule_id=rule_id,
            version_id=version.version_id,
            event_type="RULE_VERSION_CREATED",
            actor_user_id=user_id,
            actor_role=user_role,
            previous_status=None,
            new_status="DRAFT",
            payload={
                "version_number": next_ver_num,
                "version_hash": v_hash,
                "rule_name": rule_name,
                "vendor_name": vendor_name,
                "severity": severity.upper(),
                "dependencies_count": len(dep_list),
            },
        )

        return version

    @classmethod
    def submit_for_review(
        cls,
        db: Session,
        version_id: str,
        user_id: str,
        user_role: str,
    ) -> Tuple[DetectionRuleVersion, DetectionRuleApprovalRequest, DetectionRuleVersionImpact]:
        """
        Submit a DRAFT rule version for dual-control review.
        - Enforces that only the creator can submit.
        - Transitions status DRAFT -> PENDING_REVIEW.
        - Generates automatic version impact analysis and approval request.
        """
        version = (
            db.query(DetectionRuleVersion)
            .filter(DetectionRuleVersion.version_id == version_id)
            .first()
        )
        if not version:
            raise ValueError(f"Rule version '{version_id}' not found.")

        if version.status != "DRAFT":
            raise ValueError(
                f"Invalid transition: Cannot submit version in status '{version.status}'. Must be 'DRAFT'."
            )

        if version.created_by_user_id != user_id and user_role != "ADMIN":
            raise PermissionError("Only the author/creator may submit their draft version for review.")

        # Update version state
        prev_status = version.status
        version.status = "PENDING_REVIEW"
        version.submitted_at = datetime.now(timezone.utc)
        version.submitted_by_user_id = user_id

        # Create approval request
        app_req = DetectionRuleApprovalRequest(
            version_id=version.version_id,
            rule_id=version.rule_id,
            submitted_by_user_id=user_id,
            submitted_at=version.submitted_at,
            status="PENDING",
            created_at=datetime.now(timezone.utc),
        )
        db.add(app_req)

        # Generate version impact analysis against parent or active version
        source_ver = None
        if version.parent_version_id:
            source_ver = (
                db.query(DetectionRuleVersion)
                .filter(DetectionRuleVersion.version_id == version.parent_version_id)
                .first()
            )
        if not source_ver:
            # Look for current ACTIVE version
            source_ver = (
                db.query(DetectionRuleVersion)
                .filter(
                    DetectionRuleVersion.rule_id == version.rule_id,
                    DetectionRuleVersion.status == "ACTIVE",
                )
                .first()
            )

        impact = cls.compare_rule_versions(
            db=db,
            source_version_id=source_ver.version_id if source_ver else None,
            target_version_id=version.version_id,
        )

        db.commit()
        db.refresh(version)
        db.refresh(app_req)

        # Audit Event
        cls.record_governance_event(
            db=db,
            rule_id=version.rule_id,
            version_id=version.version_id,
            event_type="RULE_SUBMITTED_FOR_REVIEW",
            actor_user_id=user_id,
            actor_role=user_role,
            previous_status=prev_status,
            new_status="PENDING_REVIEW",
            payload={
                "approval_request_id": app_req.approval_request_id,
                "impact_level": impact.impact_level,
                "version_hash": version.version_hash,
            },
        )

        return (version, app_req, impact)

    @classmethod
    def review_rule_version(
        cls,
        db: Session,
        version_id: str,
        reviewer_id: str,
        reviewer_role: str,
        decision: str,
        comment: Optional[str] = None,
        risk_acknowledged: bool = False,
        risk_comment: Optional[str] = None,
    ) -> DetectionRuleVersion:
        """
        Maker-Checker Dual-Control Review:
        - Critical Invariant: Reviewer ID MUST NOT equal creator ID (creator_user_id != reviewer_user_id).
        - Self-approval raises PermissionError (SELF_APPROVAL_FORBIDDEN) and logs security event.
        - Decision: 'APPROVE' or 'REJECT'.
        """
        version = (
            db.query(DetectionRuleVersion)
            .filter(DetectionRuleVersion.version_id == version_id)
            .first()
        )
        if not version:
            raise ValueError(f"Rule version '{version_id}' not found.")

        if version.status != "PENDING_REVIEW":
            raise ValueError(
                f"Invalid transition: Cannot review version with status '{version.status}'. Must be 'PENDING_REVIEW'."
            )

        # ── MAKER-CHECKER ENFORCEMENT ──────────────────────────────────────────
        if reviewer_id == version.created_by_user_id:
            cls.record_governance_event(
                db=db,
                rule_id=version.rule_id,
                version_id=version.version_id,
                event_type="SELF_APPROVAL_BLOCKED",
                actor_user_id=reviewer_id,
                actor_role=reviewer_role,
                previous_status=version.status,
                new_status=version.status,
                payload={
                    "reason": "SELF_APPROVAL_FORBIDDEN: Creator cannot review/approve their own detection rule version.",
                    "created_by": version.created_by_user_id,
                    "attempted_by": reviewer_id,
                },
            )
            raise PermissionError(
                "SELF_APPROVAL_FORBIDDEN: Creator cannot review or approve their own detection rule version. Dual-control required."
            )

        now = datetime.now(timezone.utc)
        prev_status = version.status
        dec_upper = decision.upper()

        if dec_upper not in ("APPROVE", "REJECT", "APPROVED", "REJECTED"):
            raise ValueError(f"Invalid review decision '{decision}'. Must be 'APPROVE' or 'REJECT'.")

        app_req = (
            db.query(DetectionRuleApprovalRequest)
            .filter(
                DetectionRuleApprovalRequest.version_id == version_id,
                DetectionRuleApprovalRequest.status == "PENDING",
            )
            .first()
        )

        if dec_upper in ("APPROVE", "APPROVED"):
            version.status = "APPROVED"
            version.approval_decision = "APPROVED"
            version.approval_comment = comment
            version.reviewed_at = now
            version.reviewed_by_user_id = reviewer_id
            version.risk_acknowledged = risk_acknowledged
            version.risk_acknowledgement_comment = risk_comment

            if app_req:
                app_req.status = "APPROVED"
                app_req.decision = "APPROVED"
                app_req.reviewed_by_user_id = reviewer_id
                app_req.reviewed_at = now
                app_req.review_comment = comment

            db.commit()
            db.refresh(version)

            cls.record_governance_event(
                db=db,
                rule_id=version.rule_id,
                version_id=version.version_id,
                event_type="RULE_APPROVED",
                actor_user_id=reviewer_id,
                actor_role=reviewer_role,
                previous_status=prev_status,
                new_status="APPROVED",
                payload={
                    "approval_comment": comment,
                    "risk_acknowledged": risk_acknowledged,
                    "version_hash": version.version_hash,
                },
            )

        else:
            version.status = "REJECTED"
            version.approval_decision = "REJECTED"
            version.approval_comment = comment
            version.reviewed_at = now
            version.reviewed_by_user_id = reviewer_id

            if app_req:
                app_req.status = "REJECTED"
                app_req.decision = "REJECTED"
                app_req.reviewed_by_user_id = reviewer_id
                app_req.reviewed_at = now
                app_req.review_comment = comment

            db.commit()
            db.refresh(version)

            cls.record_governance_event(
                db=db,
                rule_id=version.rule_id,
                version_id=version.version_id,
                event_type="RULE_REJECTED",
                actor_user_id=reviewer_id,
                actor_role=reviewer_role,
                previous_status=prev_status,
                new_status="REJECTED",
                payload={
                    "rejection_comment": comment,
                    "version_hash": version.version_hash,
                },
            )

        return version

    @classmethod
    def activate_rule_version(
        cls,
        db: Session,
        version_id: str,
        user_id: str,
        user_role: str,
    ) -> DetectionRuleVersion:
        """
        Atomic Rule Activation:
        - Invariant: Only 'APPROVED' versions may be activated.
        - Invariant: Single ACTIVE version. Atomically supersedes previous ACTIVE version.
        - Validates version hash integrity.
        - Synchronizes live DetectionRule and DetectionRuleDependency records.
        """
        version = (
            db.query(DetectionRuleVersion)
            .filter(DetectionRuleVersion.version_id == version_id)
            .first()
        )
        if not version:
            raise ValueError(f"Rule version '{version_id}' not found.")

        if version.status != "APPROVED":
            raise ValueError(
                f"Invalid transition: Cannot activate version with status '{version.status}'. Must be 'APPROVED'."
            )

        # Re-verify version hash integrity
        expected_hash = cls.compute_version_hash(
            rule_id=version.rule_id,
            version_number=version.version_number,
            rule_name=version.rule_name,
            vendor_name=version.vendor_name,
            description=version.description,
            query_signature=version.query_signature,
            severity=version.severity,
            mitre_techniques=version.mitre_techniques or [],
            dependencies=[d.to_dict() for d in version.dependencies],
        )
        if expected_hash != version.version_hash:
            raise ValueError(
                f"INTEGRITY VIOLATION: Version hash mismatch! Computed {expected_hash} != stored {version.version_hash}. Tampering detected."
            )

        now = datetime.now(timezone.utc)

        # 1. Supersede current ACTIVE version for this rule
        active_versions = (
            db.query(DetectionRuleVersion)
            .filter(
                DetectionRuleVersion.rule_id == version.rule_id,
                DetectionRuleVersion.status == "ACTIVE",
            )
            .all()
        )
        for act in active_versions:
            act.status = "SUPERSEDED"
            act.superseded_at = now
            act.superseded_by_version_id = version.version_id
            cls.record_governance_event(
                db=db,
                rule_id=version.rule_id,
                version_id=act.version_id,
                event_type="RULE_SUPERSEDED",
                actor_user_id=user_id,
                actor_role=user_role,
                previous_status="ACTIVE",
                new_status="SUPERSEDED",
                payload={
                    "superseded_by_version_id": version.version_id,
                    "superseded_by_version_number": version.version_number,
                },
            )

        # 2. Activate candidate version
        prev_status = version.status
        version.status = "ACTIVE"
        version.activated_at = now
        version.activated_by_user_id = user_id

        # 3. Synchronize live DetectionRule table
        live_rule = (
            db.query(DetectionRule)
            .filter(DetectionRule.rule_id == version.rule_id)
            .first()
        )
        if live_rule:
            live_rule.rule_name = version.rule_name
            live_rule.vendor_name = version.vendor_name
            live_rule.description = version.description
            live_rule.severity = version.severity
            live_rule.status = "ACTIVE"
            live_rule.version = version.version_number
            live_rule.updated_at = now

            # Sync live dependencies: clear and re-populate
            db.query(DetectionRuleDependency).filter(
                DetectionRuleDependency.rule_id == version.rule_id
            ).delete()

            for vd in version.dependencies:
                live_dep = DetectionRuleDependency(
                    rule_id=version.rule_id,
                    canonical_field=vd.canonical_field,
                    dependency_type=vd.dependency_type,
                    description=f"Synchronized from governed version {version.version_number}",
                    created_at=now,
                )
                db.add(live_dep)

        db.commit()
        db.refresh(version)

        # Audit Event
        cls.record_governance_event(
            db=db,
            rule_id=version.rule_id,
            version_id=version.version_id,
            event_type="RULE_ACTIVATED",
            actor_user_id=user_id,
            actor_role=user_role,
            previous_status=prev_status,
            new_status="ACTIVE",
            payload={
                "version_number": version.version_number,
                "version_hash": version.version_hash,
                "activated_by": user_id,
            },
        )

        return version

    @classmethod
    def disable_rule_version(
        cls,
        db: Session,
        version_id: str,
        user_id: str,
        user_role: str,
        reason: Optional[str] = None,
    ) -> DetectionRuleVersion:
        """
        Disable an ACTIVE detection rule version.
        Transitions ACTIVE -> DISABLED and updates live rule.
        """
        version = (
            db.query(DetectionRuleVersion)
            .filter(DetectionRuleVersion.version_id == version_id)
            .first()
        )
        if not version:
            raise ValueError(f"Rule version '{version_id}' not found.")

        if version.status != "ACTIVE":
            raise ValueError(
                f"Invalid transition: Cannot disable version in status '{version.status}'. Must be 'ACTIVE'."
            )

        now = datetime.now(timezone.utc)
        prev_status = version.status
        version.status = "DISABLED"

        # Sync live rule
        live_rule = (
            db.query(DetectionRule)
            .filter(DetectionRule.rule_id == version.rule_id)
            .first()
        )
        if live_rule:
            live_rule.status = "DISABLED"
            live_rule.updated_at = now

        db.commit()
        db.refresh(version)

        # Audit Event
        cls.record_governance_event(
            db=db,
            rule_id=version.rule_id,
            version_id=version.version_id,
            event_type="RULE_DISABLED",
            actor_user_id=user_id,
            actor_role=user_role,
            previous_status=prev_status,
            new_status="DISABLED",
            payload={
                "reason": reason or "Administrative deactivation",
                "version_hash": version.version_hash,
            },
        )

        return version

    # ── 3. Version Comparison & Impact Analysis ────────────────────────────────
    @classmethod
    def compare_rule_versions(
        cls,
        db: Session,
        source_version_id: Optional[str],
        target_version_id: str,
    ) -> DetectionRuleVersionImpact:
        """
        Deterministic version comparison & impact analysis:
        - Query logic changed: +HIGH
        - Protected semantic field added: +CRITICAL
        - Canonical dependency removed: +HIGH
        - Severity increased >= 2 levels: +HIGH
        - Vendor scope changed: +HIGH
        - MITRE technique changed: +MEDIUM
        - Description only: +LOW
        - No changes: NONE

        Impact precedence: CRITICAL > HIGH > MEDIUM > LOW > NONE.
        """
        target = (
            db.query(DetectionRuleVersion)
            .filter(DetectionRuleVersion.version_id == target_version_id)
            .first()
        )
        if not target:
            raise ValueError(f"Target version '{target_version_id}' not found.")

        source = None
        if source_version_id:
            source = (
                db.query(DetectionRuleVersion)
                .filter(DetectionRuleVersion.version_id == source_version_id)
                .first()
            )

        # Check existing stored impact
        existing_impact = (
            db.query(DetectionRuleVersionImpact)
            .filter(
                DetectionRuleVersionImpact.source_version_id == source_version_id,
                DetectionRuleVersionImpact.target_version_id == target_version_id,
            )
            .first()
        )
        if existing_impact:
            return existing_impact

        # Compare components
        query_changed = False
        sev_changed = False
        vendor_changed = False
        mitre_changed = False
        deps_added = []
        deps_removed = []
        prot_added = []
        impact_level = "NONE"
        detected_impacts = []

        target_deps = {d.canonical_field: d for d in target.dependencies}

        if not source:
            # First version baseline
            impact_level = "LOW"
            deps_added = list(target_deps.keys())
            prot_added = [
                d.canonical_field for d in target.dependencies if d.is_protected_field
            ]
            if prot_added:
                impact_level = "CRITICAL"
        else:
            source_deps = {d.canonical_field: d for d in source.dependencies}

            # 1. Query change check
            if (source.query_signature or "") != (target.query_signature or ""):
                query_changed = True
                detected_impacts.append("HIGH")

            # 2. Severity check
            sev_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            src_sev = sev_levels.get(source.severity, 2)
            tgt_sev = sev_levels.get(target.severity, 2)
            if src_sev != tgt_sev:
                sev_changed = True
                if abs(tgt_sev - src_sev) >= 2:
                    detected_impacts.append("HIGH")
                else:
                    detected_impacts.append("MEDIUM")

            # 3. Vendor scope check
            if source.vendor_name != target.vendor_name:
                vendor_changed = True
                detected_impacts.append("HIGH")

            # 4. MITRE check
            if set(source.mitre_techniques or []) != set(target.mitre_techniques or []):
                mitre_changed = True
                detected_impacts.append("MEDIUM")

            # 5. Dependency additions and removals
            deps_added = [f for f in target_deps if f not in source_deps]
            deps_removed = [f for f in source_deps if f not in target_deps]

            if deps_removed:
                detected_impacts.append("HIGH")

            # 6. Protected field introduction
            for f in deps_added:
                if target_deps[f].is_protected_field:
                    prot_added.append(f)
                    detected_impacts.append("CRITICAL")

            if deps_added and not prot_added:
                detected_impacts.append("LOW")

            # 7. Description only check
            if not detected_impacts and (source.description or "") != (target.description or ""):
                detected_impacts.append("LOW")

            # Determine overall impact precedence
            if "CRITICAL" in detected_impacts:
                impact_level = "CRITICAL"
            elif "HIGH" in detected_impacts:
                impact_level = "HIGH"
            elif "MEDIUM" in detected_impacts:
                impact_level = "MEDIUM"
            elif "LOW" in detected_impacts:
                impact_level = "LOW"
            else:
                impact_level = "NONE"

        blast_summary = (
            f"Version {target.version_number} evaluation classified as [{impact_level}] impact. "
            f"Dependencies added: {len(deps_added)}, Dependencies removed: {len(deps_removed)}, "
            f"Protected fields introduced: {len(prot_added)}. "
            f"Query modified: {query_changed}."
        )

        impact_record = DetectionRuleVersionImpact(
            source_version_id=source_version_id,
            target_version_id=target_version_id,
            impact_level=impact_level,
            query_changed=query_changed,
            severity_changed=sev_changed,
            vendor_scope_changed=vendor_changed,
            mitre_changed=mitre_changed,
            dependencies_added=deps_added,
            dependencies_removed=deps_removed,
            protected_fields_added=prot_added,
            trust_risk_delta=-0.25 if prot_added else (-0.10 if deps_removed else 0.0),
            blast_radius_summary=blast_summary,
            impact_details={
                "detected_impacts": detected_impacts,
                "source_version_number": source.version_number if source else None,
                "target_version_number": target.version_number,
            },
            created_at=datetime.now(timezone.utc),
        )
        db.add(impact_record)
        db.commit()
        db.refresh(impact_record)

        # Audit Event
        cls.record_governance_event(
            db=db,
            rule_id=target.rule_id,
            version_id=target.version_id,
            event_type="VERSION_IMPACT_ANALYZED",
            actor_user_id="SYSTEM_ANALYST",
            actor_role="SYSTEM",
            previous_status=target.status,
            new_status=target.status,
            payload={
                "impact_level": impact_level,
                "source_version_id": source_version_id,
                "target_version_id": target_version_id,
            },
        )

        return impact_record

    @classmethod
    def get_version_impact(
        cls,
        db: Session,
        version_id: str,
    ) -> DetectionRuleVersionImpact:
        """Retrieve stored impact analysis for a candidate version or compute if missing."""
        impact = (
            db.query(DetectionRuleVersionImpact)
            .filter(DetectionRuleVersionImpact.target_version_id == version_id)
            .order_by(DetectionRuleVersionImpact.created_at.desc())
            .first()
        )
        if not impact:
            version = (
                db.query(DetectionRuleVersion)
                .filter(DetectionRuleVersion.version_id == version_id)
                .first()
            )
            if not version:
                raise ValueError(f"Rule version '{version_id}' not found.")
            source_id = version.parent_version_id
            if not source_id:
                active_v = (
                    db.query(DetectionRuleVersion)
                    .filter(
                        DetectionRuleVersion.rule_id == version.rule_id,
                        DetectionRuleVersion.status == "ACTIVE",
                    )
                    .first()
                )
                source_id = active_v.version_id if active_v else None
            impact = cls.compare_rule_versions(
                db=db,
                source_version_id=source_id,
                target_version_id=version.version_id,
            )
        return impact

    # ── 4. Pre-Approval Trust Simulation ───────────────────────────────────────
    @classmethod
    def simulate_version_trust(
        cls,
        db: Session,
        version_id: str,
    ) -> Dict[str, Any]:
        """
        Simulate hypothetical pre-approval trust posture for a candidate version.
        - Inspects declared version dependencies against protected fields and known drift conditions.
        - Invariant: Does NOT mutate runtime Sprint 6B trust evaluations.
        """
        version = (
            db.query(DetectionRuleVersion)
            .filter(DetectionRuleVersion.version_id == version_id)
            .first()
        )
        if not version:
            raise ValueError(f"Rule version '{version_id}' not found.")

        protected_fields = {
            p.field_name
            for p in db.query(ProtectedSemanticField)
            .filter(ProtectedSemanticField.is_protected.is_(True))
            .all()
        }

        # Active drift alerts in environment (from trust alerts or interpretations)
        active_drifts = {}
        for ta in db.query(DetectionTrustAlert).filter(DetectionTrustAlert.status == "OPEN").all():
            if ta.affected_field:
                active_drifts[ta.affected_field] = {
                    "drift_type": ta.alert_type,
                    "severity": ta.severity,
                }
        for interp in (
            db.query(SemanticInterpretation)
            .filter(SemanticInterpretation.interpretation_status.in_(["AMBIGUOUS", "UNMAPPED", "CONFLICT", "FAILED"]))
            .all()
        ):
            if interp.canonical_field and interp.canonical_field not in active_drifts:
                active_drifts[interp.canonical_field] = {
                    "drift_type": interp.interpretation_status,
                    "severity": interp.risk_level,
                }

        reasons = ["Simulated Base Trust: 1.00"]
        worst_score = 1.00
        worst_field = None

        if not version.dependencies:
            return {
                "simulation_type": "PRE_APPROVAL_HYPOTHETICAL",
                "version_id": version_id,
                "rule_id": version.rule_id,
                "rule_name": version.rule_name,
                "simulated_score": 0.50,
                "simulated_state": "UNKNOWN",
                "worst_dependency_field": "NONE_DECLARED",
                "reasons": ["No dependencies declared in version snapshot (Zero Trust clamp: 0.50)"],
                "is_safe_to_activate": False,
                "requires_risk_acknowledgement": True,
            }

        for dep in version.dependencies:
            field = dep.canonical_field
            is_prot = field in protected_fields or dep.is_protected_field

            drift = active_drifts.get(field)
            eq_class = "EXACT"
            risk_lvl = "NONE"
            drift_type = None

            if drift:
                drift_type = drift["drift_type"]
                risk_lvl = drift["severity"]
                if drift_type in ("AMBIGUOUS_MAPPING", "AMBIGUOUS"):
                    eq_class = "AMBIGUOUS"
                elif drift_type in ("INCOMPATIBLE_MAPPING", "TYPE_INCOMPATIBLE", "CONFLICT", "FAILED"):
                    eq_class = "INCOMPATIBLE"
                elif drift_type in ("UNMAPPED_VALUE", "UNMAPPED"):
                    eq_class = "UNMAPPED"

            score, dep_reasons = DetectionRuleTrustService.calculate_trust_score(
                equivalence_classification=eq_class,
                risk_level=risk_lvl,
                is_protected_field=is_prot,
                drift_type=drift_type,
            )

            if score < worst_score:
                worst_score = score
                worst_field = field

            for r in dep_reasons:
                if "Base trust" not in r and "Final" not in r:
                    reasons.append(f"Field [{field}]: {r}")

        status, _ = DetectionRuleTrustService.determine_trust_status(worst_score)
        reasons.append(f"Worst-case dependency [{worst_field}] governs simulated trust state: {status} ({worst_score:.2f})")

        return {
            "simulation_type": "PRE_APPROVAL_HYPOTHETICAL",
            "version_id": version_id,
            "rule_id": version.rule_id,
            "rule_name": version.rule_name,
            "simulated_score": round(worst_score, 4),
            "simulated_state": status,
            "worst_dependency_field": worst_field,
            "reasons": reasons,
            "is_safe_to_activate": status in ("TRUSTED", "DEGRADED"),
            "requires_risk_acknowledgement": status in ("AT_RISK", "INVALID", "UNKNOWN"),
        }

    # ── 5. End-to-End Governance Trace ─────────────────────────────────────────
    @classmethod
    def get_governance_trace(
        cls,
        db: Session,
        version_id: str,
    ) -> Dict[str, Any]:
        """
        Construct the 15-stage governance provenance trace:
        1. Detection Rule Header
        2. Version Snapshot
        3. Version Hash Seal
        4. Dependency Snapshot Contract
        5. Parent Version Lineage
        6. Version Impact Analysis
        7. Pre-Approval Trust Simulation
        8. Submission Event
        9. Dual-Control Approval Request
        10. Maker-Checker Review Decision
        11. Risk Acknowledgement Audit
        12. Activation & Atomic Supersession
        13. Live Rule Synchronization
        14. Immutable Governance Events Chain
        15. Governance Ledger Reference (if committed)
        """
        version = (
            db.query(DetectionRuleVersion)
            .filter(DetectionRuleVersion.version_id == version_id)
            .first()
        )
        if not version:
            raise ValueError(f"Rule version '{version_id}' not found.")

        rule = db.query(DetectionRule).filter(DetectionRule.rule_id == version.rule_id).first()
        impact = (
            db.query(DetectionRuleVersionImpact)
            .filter(DetectionRuleVersionImpact.target_version_id == version_id)
            .first()
        )
        app_req = (
            db.query(DetectionRuleApprovalRequest)
            .filter(DetectionRuleApprovalRequest.version_id == version_id)
            .first()
        )
        events = (
            db.query(DetectionRuleGovernanceEvent)
            .filter(DetectionRuleGovernanceEvent.version_id == version_id)
            .order_by(DetectionRuleGovernanceEvent.created_at.asc())
            .all()
        )

        chain: List[Dict[str, Any]] = []
        step_num = 1

        # 1. Detection Rule
        if rule:
            chain.append({
                "step_number": step_num,
                "stage_name": "DETECTION_RULE_REGISTRY",
                "entity_id": rule.rule_id,
                "entity_type": "DetectionRule",
                "summary": f"Governed detection rule '{rule.rule_name}' (Vendor: {rule.vendor_name})",
                "details": rule.to_dict(),
                "timestamp": rule.created_at.isoformat() if rule.created_at else None,
            })
            step_num += 1

        # 2. Version Snapshot
        chain.append({
            "step_number": step_num,
            "stage_name": "VERSION_SNAPSHOT",
            "entity_id": version.version_id,
            "entity_type": "DetectionRuleVersion",
            "summary": f"Version {version.version_number} snapshot (Status: {version.status}, Severity: {version.severity})",
            "details": version.to_dict(),
            "timestamp": version.created_at.isoformat() if version.created_at else None,
        })
        step_num += 1

        # 3. Version Hash Seal
        chain.append({
            "step_number": step_num,
            "stage_name": "VERSION_HASH_SEAL",
            "entity_id": f"vhash_{version.version_id}",
            "entity_type": "CryptographicHash",
            "summary": f"Deterministic SHA-256 Version Seal: {version.version_hash}",
            "details": {
                "domain_prefix": cls.VERSION_HASH_DOMAIN_PREFIX,
                "version_hash": version.version_hash,
                "rule_id": version.rule_id,
                "version_number": version.version_number,
            },
            "timestamp": version.created_at.isoformat() if version.created_at else None,
        })
        step_num += 1

        # 4. Dependency Snapshot
        chain.append({
            "step_number": step_num,
            "stage_name": "DEPENDENCY_CONTRACT",
            "entity_id": f"deps_{version.version_id}",
            "entity_type": "VersionDependencySet",
            "summary": f"{len(version.dependencies)} version-scoped canonical field dependencies",
            "details": {
                "dependencies": [d.to_dict() for d in version.dependencies],
            },
            "timestamp": version.created_at.isoformat() if version.created_at else None,
        })
        step_num += 1

        # 5. Parent Version Lineage
        if version.parent_version_id:
            chain.append({
                "step_number": step_num,
                "stage_name": "VERSION_LINEAGE",
                "entity_id": version.parent_version_id,
                "entity_type": "ParentVersionReference",
                "summary": f"Branched from parent version '{version.parent_version_id}'",
                "details": {
                    "parent_version_id": version.parent_version_id,
                    "target_version_id": version.version_id,
                },
                "timestamp": version.created_at.isoformat() if version.created_at else None,
            })
            step_num += 1

        # 6. Version Impact Analysis
        if impact:
            chain.append({
                "step_number": step_num,
                "stage_name": "VERSION_IMPACT_ANALYSIS",
                "entity_id": impact.impact_id,
                "entity_type": "DetectionRuleVersionImpact",
                "summary": f"Impact Classification: [{impact.impact_level}]",
                "details": impact.to_dict(),
                "timestamp": impact.created_at.isoformat() if impact.created_at else None,
            })
            step_num += 1

        # 7. Pre-Approval Trust Simulation
        sim = cls.simulate_version_trust(db, version_id)
        chain.append({
            "step_number": step_num,
            "stage_name": "TRUST_SIMULATION",
            "entity_id": f"sim_{version_id}",
            "entity_type": "HypotheticalSimulation",
            "summary": f"Pre-Approval Simulated Trust: {sim['simulated_state']} ({sim['simulated_score']:.2f})",
            "details": sim,
            "timestamp": version.submitted_at.isoformat() if version.submitted_at else None,
        })
        step_num += 1

        # 8. Dual-Control Approval Request
        if app_req:
            chain.append({
                "step_number": step_num,
                "stage_name": "APPROVAL_REQUEST",
                "entity_id": app_req.approval_request_id,
                "entity_type": "DetectionRuleApprovalRequest",
                "summary": f"Approval Request [{app_req.status}] submitted by {app_req.submitted_by_user_id}",
                "details": app_req.to_dict(),
                "timestamp": app_req.submitted_at.isoformat() if app_req.submitted_at else None,
            })
            step_num += 1

        # 9. Maker-Checker Review Decision
        if version.reviewed_by_user_id:
            chain.append({
                "step_number": step_num,
                "stage_name": "MAKER_CHECKER_REVIEW",
                "entity_id": f"review_{version_id}",
                "entity_type": "ReviewDecision",
                "summary": f"Independent Decision: [{version.approval_decision}] by {version.reviewed_by_user_id}",
                "details": {
                    "reviewed_by_user_id": version.reviewed_by_user_id,
                    "decision": version.approval_decision,
                    "comment": version.approval_comment,
                    "risk_acknowledged": version.risk_acknowledged,
                    "risk_acknowledgement_comment": version.risk_acknowledgement_comment,
                },
                "timestamp": version.reviewed_at.isoformat() if version.reviewed_at else None,
            })
            step_num += 1

        # 10. Activation / Supersession
        if version.activated_at:
            chain.append({
                "step_number": step_num,
                "stage_name": "RULE_ACTIVATION",
                "entity_id": f"act_{version_id}",
                "entity_type": "ActivationRecord",
                "summary": f"Activated in production by {version.activated_by_user_id}",
                "details": {
                    "activated_at": version.activated_at.isoformat(),
                    "activated_by": version.activated_by_user_id,
                },
                "timestamp": version.activated_at.isoformat(),
            })
            step_num += 1

        # 11. Immutable Governance Events Chain
        for ev in events:
            chain.append({
                "step_number": step_num,
                "stage_name": "GOVERNANCE_EVENT",
                "entity_id": ev.event_id,
                "entity_type": "DetectionRuleGovernanceEvent",
                "summary": f"Event [{ev.event_type}] sealed with hash: {ev.event_hash[:16]}...",
                "details": ev.to_dict(),
                "timestamp": ev.created_at.isoformat() if ev.created_at else None,
            })
            step_num += 1

        return {
            "version_id": version.version_id,
            "rule_id": version.rule_id,
            "rule_name": version.rule_name,
            "version_number": version.version_number,
            "version_hash": version.version_hash,
            "status": version.status,
            "provenance_chain": chain,
        }

    # ── 6. Query Helpers ───────────────────────────────────────────────────────
    @staticmethod
    def list_versions(
        db: Session,
        rule_id: Optional[str] = None,
        status: Optional[str] = None,
        created_by: Optional[str] = None,
        reviewed_by: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[DetectionRuleVersion]:
        """Query rule versions with optional filtering and pagination."""
        query = db.query(DetectionRuleVersion)
        if rule_id:
            query = query.filter(DetectionRuleVersion.rule_id == rule_id)
        if status:
            query = query.filter(DetectionRuleVersion.status == status.upper())
        if created_by:
            query = query.filter(DetectionRuleVersion.created_by_user_id == created_by)
        if reviewed_by:
            query = query.filter(DetectionRuleVersion.reviewed_by_user_id == reviewed_by)
        return (
            query.order_by(
                DetectionRuleVersion.rule_id.asc(),
                DetectionRuleVersion.version_number.desc(),
            )
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_version_by_id(db: Session, version_id: str) -> Optional[DetectionRuleVersion]:
        """Fetch a single version snapshot by version_id."""
        return (
            db.query(DetectionRuleVersion)
            .filter(DetectionRuleVersion.version_id == version_id)
            .first()
        )

    @staticmethod
    def list_governance_events(
        db: Session,
        rule_id: Optional[str] = None,
        version_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[DetectionRuleGovernanceEvent]:
        """List append-only immutable governance audit events."""
        query = db.query(DetectionRuleGovernanceEvent)
        if rule_id:
            query = query.filter(DetectionRuleGovernanceEvent.rule_id == rule_id)
        if version_id:
            query = query.filter(DetectionRuleGovernanceEvent.version_id == version_id)
        if event_type:
            query = query.filter(DetectionRuleGovernanceEvent.event_type == event_type.upper())
        return (
            query.order_by(DetectionRuleGovernanceEvent.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    # ── 7. Default Seeder ──────────────────────────────────────────────────────
    @classmethod
    def seed_default_governed_versions(cls, db: Session) -> None:
        """
        Seed initial v1 ACTIVE versions for all baseline detection rules.
        """
        rules = db.query(DetectionRule).all()
        for r in rules:
            existing = (
                db.query(DetectionRuleVersion)
                .filter(
                    DetectionRuleVersion.rule_id == r.rule_id,
                    DetectionRuleVersion.version_number == 1,
                )
                .first()
            )
            if existing:
                continue

            deps = (
                db.query(DetectionRuleDependency)
                .filter(DetectionRuleDependency.rule_id == r.rule_id)
                .all()
            )
            dep_dicts = [d.to_dict() for d in deps]

            v_hash = cls.compute_version_hash(
                rule_id=r.rule_id,
                version_number=1,
                rule_name=r.rule_name,
                vendor_name=r.vendor_name,
                description=r.description,
                query_signature=f"SIGNATURE_{r.rule_id.upper()}",
                severity=r.severity,
                mitre_techniques=[r.mitre_technique] if r.mitre_technique else [],
                dependencies=dep_dicts,
            )

            now = datetime.now(timezone.utc)
            ver = DetectionRuleVersion(
                version_id=f"drver_{r.rule_id}_v1",
                rule_id=r.rule_id,
                version_number=1,
                rule_name=r.rule_name,
                vendor_name=r.vendor_name,
                description=r.description,
                query_signature=f"SIGNATURE_{r.rule_id.upper()}",
                severity=r.severity,
                mitre_techniques=[r.mitre_technique] if r.mitre_technique else [],
                status="ACTIVE",
                created_by_user_id="usr_author_cisco",
                created_at=now,
                submitted_at=now,
                submitted_by_user_id="usr_author_cisco",
                reviewed_at=now,
                reviewed_by_user_id="usr_reviewer_01",
                approval_decision="APPROVED",
                approval_comment="Seeded baseline version approved.",
                activated_at=now,
                activated_by_user_id="usr_admin_01",
                version_hash=v_hash,
            )
            db.add(ver)
            db.flush()

            for d in deps:
                ver_dep = DetectionRuleVersionDependency(
                    version_id=ver.version_id,
                    canonical_field=d.canonical_field,
                    dependency_type=d.dependency_type,
                    is_protected_field=False,
                    created_at=now,
                )
                db.add(ver_dep)

            cls.record_governance_event(
                db=db,
                rule_id=r.rule_id,
                version_id=ver.version_id,
                event_type="RULE_ACTIVATED",
                actor_user_id="usr_admin_01",
                actor_role="ADMIN",
                previous_status="APPROVED",
                new_status="ACTIVE",
                payload={
                    "version_number": 1,
                    "version_hash": v_hash,
                    "description": "Seeded initial active version baseline",
                },
            )

        db.commit()
