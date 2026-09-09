"""
services/semantic_policy_service.py
-----------------------------------
Service layer for Semantic Policy Registry, Rules, and Protected Semantic Fields.

Sprint 3A — Semantic Policy Registry & Backend Management.
Enforces vendor/source-profile-scoped semantic interpretation to prevent global
semantic assumptions while safeguarding critical security-sensitive fields.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.models.semantic_policy import (
    ProtectedSemanticField,
    SemanticPolicy,
    SemanticPolicyRule,
)
from app.schemas.semantic_policy import SemanticPolicyCreateRequest

logger = logging.getLogger("sentinel.services.semantic_policy")


DEFAULT_PROTECTED_FIELDS = [
    {
        "field_name": "action.result",
        "criticality": "CRITICAL",
        "description": "Canonical security action outcome (ALLOWED, DENIED, MONITORED, DROPPED). Critical for firewall and access control telemetry.",
        "is_protected": True,
    },
    {
        "field_name": "severity",
        "criticality": "HIGH",
        "description": "Standardized event severity classification. Governs alert prioritization and triage urgency.",
        "is_protected": True,
    },
    {
        "field_name": "authentication.outcome",
        "criticality": "CRITICAL",
        "description": "Identity verification result (SUCCESS, FAILURE). Crucial for brute force and anomalous authentication detection.",
        "is_protected": True,
    },
]

DEFAULT_POLICIES = [
    {
        "policy_id": "spol_cisco_asa_v0",
        "policy_name": "Cisco ASA Semantic Policy (Legacy v0)",
        "vendor_name": "Cisco ASA",
        "source_profile_id": "sp_firewall_syslog",
        "version": 0,
        "status": "SUPERSEDED",
        "description": "Legacy baseline semantic mappings for Cisco ASA prior to policy migration.",
        "supersedes_policy_id": None,
        "rules": [
            {
                "rule_id": "srule_cisco_v0_01",
                "source_field": "action",
                "source_value": "PERMIT",
                "canonical_field": "action.result",
                "canonical_value": "MONITORED",
                "equivalence_classification": "AMBIGUOUS",
                "risk_level": "MEDIUM",
                "description": "Legacy observation mapping before active firewall enforcement rules were ratified.",
            },
            {
                "rule_id": "srule_cisco_v0_02",
                "source_field": "action",
                "source_value": "DENY",
                "canonical_field": "action.result",
                "canonical_value": "DENIED",
                "equivalence_classification": "EQUIVALENT",
                "risk_level": "LOW",
                "description": "Direct equivalence: Cisco DENY directly maps to canonical DENIED",
            },
        ],
    },
    {
        "policy_id": "spol_cisco_asa_v1",
        "policy_name": "Cisco ASA Semantic Policy",
        "vendor_name": "Cisco ASA",
        "source_profile_id": "sp_firewall_syslog",
        "version": 1,
        "status": "ACTIVE",
        "description": "Current active semantic mappings for Cisco ASA syslog telemetry. Interprets PERMIT as ALLOWED.",
        "supersedes_policy_id": "spol_cisco_asa_v0",
        "rules": [
            {
                "rule_id": "srule_cisco_01",
                "source_field": "action",
                "source_value": "ALLOW",
                "canonical_field": "action.result",
                "canonical_value": "ALLOWED",
                "equivalence_classification": "EQUIVALENT",
                "risk_level": "LOW",
                "description": "Direct equivalence: Cisco ALLOW directly maps to canonical ALLOWED",
            },
            {
                "rule_id": "srule_cisco_02",
                "source_field": "action",
                "source_value": "DENY",
                "canonical_field": "action.result",
                "canonical_value": "DENIED",
                "equivalence_classification": "EQUIVALENT",
                "risk_level": "LOW",
                "description": "Direct equivalence: Cisco DENY directly maps to canonical DENIED",
            },
            {
                "rule_id": "srule_cisco_03",
                "source_field": "action",
                "source_value": "PERMIT",
                "canonical_field": "action.result",
                "canonical_value": "ALLOWED",
                "equivalence_classification": "COMPATIBLE",
                "risk_level": "LOW",
                "description": "Compatible mapping: Cisco ASA PERMIT indicates traffic was permitted/allowed",
            },
        ],
    },
    {
        "policy_id": "spol_cisco_asa_v2_draft",
        "policy_name": "Cisco ASA Semantic Policy (Candidate v2)",
        "vendor_name": "Cisco ASA",
        "source_profile_id": "sp_firewall_syslog",
        "version": 2,
        "status": "DRAFT",
        "description": "Candidate policy proposal: Re-evaluates PERMIT to MONITORED for zero-trust shadow telemetry and adds BYPASS rule.",
        "supersedes_policy_id": "spol_cisco_asa_v1",
        "rules": [
            {
                "rule_id": "srule_cisco_v2_01",
                "source_field": "action",
                "source_value": "ALLOW",
                "canonical_field": "action.result",
                "canonical_value": "ALLOWED",
                "equivalence_classification": "EQUIVALENT",
                "risk_level": "LOW",
                "description": "Direct equivalence: Cisco ALLOW directly maps to canonical ALLOWED",
            },
            {
                "rule_id": "srule_cisco_v2_02",
                "source_field": "action",
                "source_value": "DENY",
                "canonical_field": "action.result",
                "canonical_value": "DENIED",
                "equivalence_classification": "EQUIVALENT",
                "risk_level": "LOW",
                "description": "Direct equivalence: Cisco DENY directly maps to canonical DENIED",
            },
            {
                "rule_id": "srule_cisco_v2_03",
                "source_field": "action",
                "source_value": "PERMIT",
                "canonical_field": "action.result",
                "canonical_value": "MONITORED",
                "equivalence_classification": "AMBIGUOUS",
                "risk_level": "MEDIUM",
                "description": "Proposed candidate change: Reclassifies PERMIT to MONITORED for deep inspection observation.",
            },
            {
                "rule_id": "srule_cisco_v2_04",
                "source_field": "action",
                "source_value": "BYPASS",
                "canonical_field": "action.result",
                "canonical_value": "ALLOWED",
                "equivalence_classification": "COMPATIBLE",
                "risk_level": "LOW",
                "description": "New rule: Explicit bypass rules allowed under zero-trust inspection.",
            },
        ],
    },
    {
        "policy_id": "spol_demo_vendor_v1",
        "policy_name": "Demo Vendor Semantic Policy",
        "vendor_name": "Demo Vendor",
        "source_profile_id": "sp_demo_vendor",
        "version": 1,
        "status": "ACTIVE",
        "description": "Semantic mappings for Demo Vendor telemetry. Interprets PERMIT as MONITORED due to vendor observation mode.",
        "supersedes_policy_id": None,
        "rules": [
            {
                "rule_id": "srule_demo_01",
                "source_field": "action",
                "source_value": "PERMIT",
                "canonical_field": "action.result",
                "canonical_value": "MONITORED",
                "equivalence_classification": "AMBIGUOUS",
                "risk_level": "MEDIUM",
                "description": "Ambiguous mapping: In Demo Vendor appliances, PERMIT indicates shadow/monitored pass-through without active policy enforcement",
            },
            {
                "rule_id": "srule_demo_02",
                "source_field": "action",
                "source_value": "BLOCK",
                "canonical_field": "action.result",
                "canonical_value": "DENIED",
                "equivalence_classification": "EQUIVALENT",
                "risk_level": "LOW",
                "description": "Direct equivalence: Demo Vendor BLOCK maps to canonical DENIED",
            },
            {
                "rule_id": "srule_demo_03",
                "source_field": "action",
                "source_value": "PASS",
                "canonical_field": "action.result",
                "canonical_value": "ALLOWED",
                "equivalence_classification": "COMPATIBLE",
                "risk_level": "LOW",
                "description": "Compatible mapping: Demo Vendor PASS indicates allowed bypass",
            },
        ],
    },
]


class SemanticPolicyService:
    """Service for managing Semantic Policies, Rules, and Protected Semantic Fields."""

    @staticmethod
    def seed_defaults(db: Session) -> Dict[str, int]:
        """
        Idempotently seeds default protected fields and demo semantic policies.
        """
        seeded_fields = 0
        seeded_policies = 0
        seeded_rules = 0

        # 1. Seed Protected Fields
        for f_data in DEFAULT_PROTECTED_FIELDS:
            existing_f = (
                db.query(ProtectedSemanticField)
                .filter(ProtectedSemanticField.field_name == f_data["field_name"])
                .first()
            )
            if not existing_f:
                new_f = ProtectedSemanticField(
                    field_name=f_data["field_name"],
                    criticality=f_data["criticality"],
                    description=f_data["description"],
                    is_protected=f_data["is_protected"],
                )
                db.add(new_f)
                seeded_fields += 1
        db.commit()

        default_active_ids = {p["policy_id"] for p in DEFAULT_POLICIES if p["status"] == "ACTIVE"}
        for p_data in DEFAULT_POLICIES:
            existing_p = (
                db.query(SemanticPolicy)
                .filter(SemanticPolicy.policy_id == p_data["policy_id"])
                .first()
            )
            if existing_p:
                existing_p.status = p_data["status"]
                if not existing_p.supersedes_policy_id and p_data.get("supersedes_policy_id"):
                    existing_p.supersedes_policy_id = p_data.get("supersedes_policy_id")
            else:
                policy = SemanticPolicy(
                    policy_id=p_data["policy_id"],
                    policy_name=p_data["policy_name"],
                    vendor_name=p_data["vendor_name"],
                    source_profile_id=p_data["source_profile_id"],
                    version=p_data["version"],
                    status=p_data["status"],
                    description=p_data["description"],
                    supersedes_policy_id=p_data.get("supersedes_policy_id"),
                )
                db.add(policy)
                db.flush()

                for r_data in p_data.get("rules", []):
                    rule = SemanticPolicyRule(
                        rule_id=r_data["rule_id"],
                        policy_id=policy.policy_id,
                        source_field=r_data["source_field"],
                        source_value=r_data["source_value"],
                        canonical_field=r_data["canonical_field"],
                        canonical_value=r_data["canonical_value"],
                        equivalence_classification=r_data["equivalence_classification"],
                        risk_level=r_data["risk_level"],
                        description=r_data["description"],
                    )
                    db.add(rule)
                    seeded_rules += 1

                seeded_policies += 1

        # Clean up any non-default ACTIVE policies for seeded vendors (e.g. from runtime tests)
        default_active_ids = {p["policy_id"] for p in DEFAULT_POLICIES if p["status"] == "ACTIVE"}
        for p_data in DEFAULT_POLICIES:
            if p_data["status"] == "ACTIVE":
                other_actives = (
                    db.query(SemanticPolicy)
                    .filter(
                        SemanticPolicy.vendor_name == p_data["vendor_name"],
                        SemanticPolicy.status == "ACTIVE",
                        ~SemanticPolicy.policy_id.in_(default_active_ids),
                    )
                    .all()
                )
                for o_p in other_actives:
                    o_p.status = "SUPERSEDED"

        db.commit()

        logger.info(
            f"Semantic registry seeding complete: {seeded_fields} fields, {seeded_policies} policies, {seeded_rules} rules"
        )
        return {
            "seeded_fields": seeded_fields,
            "seeded_policies": seeded_policies,
            "seeded_rules": seeded_rules,
        }

    @staticmethod
    def get_all_policies(db: Session) -> List[Dict[str, Any]]:
        """
        Retrieves all semantic policies with rule counts.
        """
        policies = (
            db.query(SemanticPolicy)
            .options(joinedload(SemanticPolicy.rules))
            .order_by(SemanticPolicy.created_at.asc())
            .all()
        )
        return [p.to_dict() for p in policies]

    @staticmethod
    def get_policy_by_id(db: Session, policy_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a single semantic policy by policy_id including all scoped rules.
        """
        policy = (
            db.query(SemanticPolicy)
            .options(joinedload(SemanticPolicy.rules))
            .filter(SemanticPolicy.policy_id == policy_id)
            .first()
        )
        if not policy:
            return None
        return policy.to_dict()

    @staticmethod
    def get_all_protected_fields(db: Session) -> List[Dict[str, Any]]:
        """
        Retrieves all protected semantic fields.
        """
        fields = (
            db.query(ProtectedSemanticField)
            .order_by(ProtectedSemanticField.criticality.desc(), ProtectedSemanticField.field_name.asc())
            .all()
        )
        return [f.to_dict() for f in fields]

    @staticmethod
    def create_policy(db: Session, request: SemanticPolicyCreateRequest) -> Dict[str, Any]:
        """
        Creates a new semantic policy.
        Enforces that newly created policies always default to DRAFT.
        """
        policy_id = request.policy_id or f"spol_{uuid.uuid4().hex[:12]}"

        # Check for existing policy_id collision
        existing = (
            db.query(SemanticPolicy)
            .filter(SemanticPolicy.policy_id == policy_id)
            .first()
        )
        if existing:
            raise ValueError(f"Semantic policy with policy_id '{policy_id}' already exists")

        # Create policy entity with forced DRAFT status
        new_policy = SemanticPolicy(
            policy_id=policy_id,
            policy_name=request.policy_name,
            vendor_name=request.vendor_name,
            source_profile_id=request.source_profile_id,
            version=request.version or 1,
            status="DRAFT",  # Forced DRAFT state for all newly created policies
            description=request.description,
            supersedes_policy_id=request.supersedes_policy_id,
        )
        db.add(new_policy)
        db.flush()

        # Add initial rules if provided
        if request.rules:
            for rule_data in request.rules:
                r_id = rule_data.rule_id or f"srule_{uuid.uuid4().hex[:12]}"
                rule = SemanticPolicyRule(
                    rule_id=r_id,
                    policy_id=new_policy.policy_id,
                    source_field=rule_data.source_field,
                    source_value=rule_data.source_value,
                    canonical_field=rule_data.canonical_field,
                    canonical_value=rule_data.canonical_value,
                    equivalence_classification=rule_data.equivalence_classification,
                    risk_level=rule_data.risk_level,
                    description=rule_data.description,
                )
                db.add(rule)

        db.commit()
        db.refresh(new_policy)
        return new_policy.to_dict()

    @staticmethod
    def compare_policies(db: Session, source_policy_id: str, target_policy_id: str) -> Dict[str, Any]:
        """
        Performs a read-only deterministic semantic comparison between two policy versions.
        Categorizes rules into:
        - unchanged_rules
        - added_rules
        - removed_rules
        - changed_rules (with old/new values, classification shift, and calculated semantic impact)
        """
        source_policy = SemanticPolicyService.get_policy_by_id(db, source_policy_id)
        if not source_policy:
            raise ValueError(f"Source policy '{source_policy_id}' not found.")

        target_policy = SemanticPolicyService.get_policy_by_id(db, target_policy_id)
        if not target_policy:
            raise ValueError(f"Target policy '{target_policy_id}' not found.")

        # Map rules by composite key (source_field.lower(), source_value.lower())
        source_rules = {
            (r["source_field"].strip().lower(), r["source_value"].strip().lower()): r
            for r in source_policy.get("rules", [])
        }
        target_rules = {
            (r["source_field"].strip().lower(), r["source_value"].strip().lower()): r
            for r in target_policy.get("rules", [])
        }

        unchanged_rules = []
        changed_rules = []
        added_rules = []
        removed_rules = []

        all_keys = set(source_rules.keys()).union(set(target_rules.keys()))

        # Get protected field names
        protected_fields = {
            f["field_name"].strip().lower()
            for f in SemanticPolicyService.get_all_protected_fields(db)
        }

        for key in sorted(all_keys):
            s_rule = source_rules.get(key)
            t_rule = target_rules.get(key)

            if s_rule and t_rule:
                # Check for equivalence in canonical meaning
                is_canonical_same = (
                    s_rule["canonical_field"] == t_rule["canonical_field"]
                    and s_rule["canonical_value"] == t_rule["canonical_value"]
                    and s_rule["equivalence_classification"] == t_rule["equivalence_classification"]
                )
                if is_canonical_same:
                    unchanged_rules.append(t_rule)
                else:
                    # Semantic change detected
                    is_canonical_val_changed = s_rule["canonical_value"] != t_rule["canonical_value"]
                    is_protected = (
                        t_rule["canonical_field"].strip().lower() in protected_fields
                        or s_rule["canonical_field"].strip().lower() in protected_fields
                    )

                    impact = "LOW"
                    if is_canonical_val_changed or is_protected:
                        impact = "HIGH"
                    elif s_rule["equivalence_classification"] != t_rule["equivalence_classification"]:
                        impact = "MEDIUM"

                    changed_rules.append({
                        "source_field": t_rule["source_field"],
                        "source_value": t_rule["source_value"],
                        "old_canonical_field": s_rule["canonical_field"],
                        "old_canonical_value": s_rule["canonical_value"],
                        "old_classification": s_rule["equivalence_classification"],
                        "old_risk_level": s_rule["risk_level"],
                        "new_canonical_field": t_rule["canonical_field"],
                        "new_canonical_value": t_rule["canonical_value"],
                        "new_classification": t_rule["equivalence_classification"],
                        "new_risk_level": t_rule["risk_level"],
                        "semantic_impact": impact,
                        "is_protected_field": is_protected,
                        "description": t_rule.get("description"),
                    })
            elif t_rule and not s_rule:
                added_rules.append(t_rule)
            elif s_rule and not t_rule:
                removed_rules.append(s_rule)

        return {
            "source_policy": {
                "policy_id": source_policy["policy_id"],
                "policy_name": source_policy["policy_name"],
                "vendor_name": source_policy["vendor_name"],
                "version": source_policy["version"],
                "status": source_policy["status"],
            },
            "target_policy": {
                "policy_id": target_policy["policy_id"],
                "policy_name": target_policy["policy_name"],
                "vendor_name": target_policy["vendor_name"],
                "version": target_policy["version"],
                "status": target_policy["status"],
            },
            "summary": {
                "total_source_rules": len(source_rules),
                "total_target_rules": len(target_rules),
                "unchanged_count": len(unchanged_rules),
                "changed_count": len(changed_rules),
                "added_count": len(added_rules),
                "removed_count": len(removed_rules),
                "has_high_impact_changes": any(c["semantic_impact"] == "HIGH" for c in changed_rules),
            },
            "unchanged_rules": unchanged_rules,
            "changed_rules": changed_rules,
            "added_rules": added_rules,
            "removed_rules": removed_rules,
        }

