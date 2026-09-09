"""
services/detection_rule_service.py
-----------------------------------
Service layer for the Detection Rule Registry & Canonical Field Dependency
Mapping.

Sprint 6A — Detection Rule Registry & Canonical Field Dependency Mapping.

Provides:
- CRUD for detection rules (always created as DRAFT)
- Canonical field dependency registration
- Field impact analysis (which rules depend on a given canonical field)
- Dependency graph construction for visualization
- Seed demonstration detection rules

Architectural Constraints:
- Detection rules MUST NOT mutate raw evidence or normalized events.
- New detection rules are always created in DRAFT status.
- No execution engine — metadata registration only.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.detection_rule import DetectionRule, DetectionRuleDependency

logger = logging.getLogger("sentinel.services.detection_rule")

# ── Known canonical fields from NormalizedEvent model ──────────────────────────
CANONICAL_FIELDS = [
    "action",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "severity",
    "user_name",
    "hostname",
    "process_name",
    "process_id",
    "class_name",
    "activity_name",
    "event_time",
    "source_name",
    "source_type",
]

# ── Seed Detection Rules ──────────────────────────────────────────────────────
SEED_RULES = [
    {
        "rule_id": "drule_fw_deny_scan",
        "rule_name": "Firewall Deny Port Scan Detection",
        "vendor_name": "Cisco ASA",
        "description": (
            "Detects repeated firewall DENY actions across multiple destination "
            "ports from the same source IP, indicating potential port scanning activity."
        ),
        "severity": "HIGH",
        "status": "ACTIVE",
        "version": 1,
        "mitre_tactic": "TA0043: Reconnaissance",
        "mitre_technique": "T1046: Network Service Discovery",
        "dependencies": [
            {"canonical_field": "action", "dependency_type": "REQUIRED", "description": "Must evaluate DENY actions"},
            {"canonical_field": "src_ip", "dependency_type": "REQUIRED", "description": "Source IP for correlation"},
            {"canonical_field": "dst_port", "dependency_type": "REQUIRED", "description": "Destination ports for scan pattern"},
            {"canonical_field": "dst_ip", "dependency_type": "OPTIONAL", "description": "Destination IP for scoping"},
            {"canonical_field": "event_time", "dependency_type": "REQUIRED", "description": "Temporal windowing for rate analysis"},
        ],
    },
    {
        "rule_id": "drule_brute_force",
        "rule_name": "Authentication Brute Force Detection",
        "vendor_name": "ANY",
        "description": (
            "Detects repeated authentication failures from the same source, "
            "indicating credential stuffing or brute-force password attacks."
        ),
        "severity": "CRITICAL",
        "status": "ACTIVE",
        "version": 1,
        "mitre_tactic": "TA0006: Credential Access",
        "mitre_technique": "T1110: Brute Force",
        "dependencies": [
            {"canonical_field": "action", "dependency_type": "REQUIRED", "description": "Must evaluate FAILURE actions"},
            {"canonical_field": "user_name", "dependency_type": "REQUIRED", "description": "Target username for correlation"},
            {"canonical_field": "src_ip", "dependency_type": "REQUIRED", "description": "Attack source IP"},
            {"canonical_field": "event_time", "dependency_type": "REQUIRED", "description": "Temporal windowing for rate analysis"},
            {"canonical_field": "severity", "dependency_type": "ENRICHMENT", "description": "Severity enrichment for alert triage"},
        ],
    },
    {
        "rule_id": "drule_lateral_move",
        "rule_name": "Lateral Movement Detection",
        "vendor_name": "ANY",
        "description": (
            "Detects internal-to-internal network traffic patterns suggestive "
            "of lateral movement within a compromised network segment."
        ),
        "severity": "HIGH",
        "status": "DRAFT",
        "version": 1,
        "mitre_tactic": "TA0008: Lateral Movement",
        "mitre_technique": "T1021: Remote Services",
        "dependencies": [
            {"canonical_field": "src_ip", "dependency_type": "REQUIRED", "description": "Internal source host"},
            {"canonical_field": "dst_ip", "dependency_type": "REQUIRED", "description": "Internal destination host"},
            {"canonical_field": "dst_port", "dependency_type": "REQUIRED", "description": "Service port (RDP, SSH, SMB)"},
            {"canonical_field": "protocol", "dependency_type": "REQUIRED", "description": "Transport protocol filter"},
            {"canonical_field": "hostname", "dependency_type": "OPTIONAL", "description": "Endpoint hostname for context"},
        ],
    },
    {
        "rule_id": "drule_priv_escalation",
        "rule_name": "Privilege Escalation Alert",
        "vendor_name": "ANY",
        "description": (
            "Detects suspicious process execution patterns indicative of "
            "privilege escalation attempts on endpoint systems."
        ),
        "severity": "CRITICAL",
        "status": "DRAFT",
        "version": 1,
        "mitre_tactic": "TA0004: Privilege Escalation",
        "mitre_technique": "T1068: Exploitation for Privilege Escalation",
        "dependencies": [
            {"canonical_field": "process_name", "dependency_type": "REQUIRED", "description": "Suspicious process identifier"},
            {"canonical_field": "user_name", "dependency_type": "REQUIRED", "description": "Actor performing escalation"},
            {"canonical_field": "hostname", "dependency_type": "REQUIRED", "description": "Target endpoint"},
            {"canonical_field": "severity", "dependency_type": "ENRICHMENT", "description": "Severity context for triage"},
            {"canonical_field": "event_time", "dependency_type": "REQUIRED", "description": "Temporal analysis"},
        ],
    },
]


class DetectionRuleService:
    """Service for detection rule registry management."""

    @staticmethod
    def seed_defaults(db: Session) -> None:
        """
        Seed demonstration detection rules and their field dependencies
        idempotently. Skips rules that already exist by rule_id.
        """
        for seed in SEED_RULES:
            seed_copy = dict(seed)
            deps_data = seed_copy.pop("dependencies", [])

            existing = (
                db.query(DetectionRule)
                .filter(DetectionRule.rule_id == seed["rule_id"])
                .first()
            )
            if existing:
                # If existing rule has no dependencies, restore them
                dep_count = (
                    db.query(DetectionRuleDependency)
                    .filter(DetectionRuleDependency.rule_id == existing.rule_id)
                    .count()
                )
                if dep_count == 0 and deps_data:
                    for dep in deps_data:
                        dependency = DetectionRuleDependency(
                            dependency_id=f"ddep_{uuid.uuid4().hex[:12]}",
                            rule_id=existing.rule_id,
                            canonical_field=dep["canonical_field"],
                            dependency_type=dep["dependency_type"],
                            description=dep.get("description"),
                        )
                        db.add(dependency)
                continue

            rule = DetectionRule(**seed_copy)
            db.add(rule)
            db.flush()  # Get rule_id persisted

            for dep in deps_data:
                dependency = DetectionRuleDependency(
                    dependency_id=f"ddep_{uuid.uuid4().hex[:12]}",
                    rule_id=rule.rule_id,
                    canonical_field=dep["canonical_field"],
                    dependency_type=dep["dependency_type"],
                    description=dep.get("description"),
                )
                db.add(dependency)

            logger.info("Seeded detection rule: %s (%s)", rule.rule_name, rule.rule_id)

        db.commit()
        logger.info("Detection rule seeding complete.")

    @staticmethod
    def create_rule(
        db: Session,
        rule_name: str,
        vendor_name: str,
        description: Optional[str] = None,
        severity: str = "MEDIUM",
        mitre_tactic: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        created_by: Optional[str] = None,
        dependencies: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Create a new detection rule. Always starts as DRAFT.
        Optionally registers canonical field dependencies at creation.
        """
        rule = DetectionRule(
            rule_id=f"drule_{uuid.uuid4().hex[:12]}",
            rule_name=rule_name,
            vendor_name=vendor_name,
            description=description,
            severity=severity.upper() if severity else "MEDIUM",
            status="DRAFT",  # Enforced: always DRAFT on creation
            version=1,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            created_by=created_by,
        )
        db.add(rule)
        db.flush()

        if dependencies:
            for dep in dependencies:
                dependency = DetectionRuleDependency(
                    dependency_id=f"ddep_{uuid.uuid4().hex[:12]}",
                    rule_id=rule.rule_id,
                    canonical_field=dep["canonical_field"],
                    dependency_type=dep.get("dependency_type", "REQUIRED"),
                    description=dep.get("description"),
                )
                db.add(dependency)

        db.commit()
        db.refresh(rule)
        logger.info("Created detection rule: %s (%s) by %s", rule.rule_name, rule.rule_id, created_by)
        return rule.to_dict()

    @staticmethod
    def get_rules(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        vendor_name: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Retrieve paginated detection rules with optional filters."""
        query = db.query(DetectionRule)

        if status:
            query = query.filter(DetectionRule.status == status.upper())
        if vendor_name:
            query = query.filter(DetectionRule.vendor_name == vendor_name)
        if severity:
            query = query.filter(DetectionRule.severity == severity.upper())

        total = query.count()
        rules = query.order_by(DetectionRule.created_at.desc()).offset(offset).limit(limit).all()
        return [r.to_dict() for r in rules], total

    @staticmethod
    def get_rule_by_id(db: Session, rule_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single detection rule with all dependencies."""
        rule = (
            db.query(DetectionRule)
            .filter(DetectionRule.rule_id == rule_id)
            .first()
        )
        return rule.to_dict() if rule else None

    @staticmethod
    def get_field_impact(db: Session, canonical_field: str) -> Dict[str, Any]:
        """
        Impact analysis: Find all detection rules that depend on a given
        canonical field. Used to understand what breaks if a semantic policy
        changes the interpretation of this field.
        """
        deps = (
            db.query(DetectionRuleDependency)
            .filter(DetectionRuleDependency.canonical_field == canonical_field)
            .all()
        )

        impacted_rules = []
        for dep in deps:
            rule = (
                db.query(DetectionRule)
                .filter(DetectionRule.rule_id == dep.rule_id)
                .first()
            )
            if rule:
                impacted_rules.append({
                    "rule_id": rule.rule_id,
                    "rule_name": rule.rule_name,
                    "vendor_name": rule.vendor_name,
                    "severity": rule.severity,
                    "status": rule.status,
                    "dependency_type": dep.dependency_type,
                })

        return {
            "canonical_field": canonical_field,
            "total_dependent_rules": len(impacted_rules),
            "impacted_rules": impacted_rules,
        }

    @staticmethod
    def get_dependency_graph(db: Session) -> Dict[str, Any]:
        """
        Build the complete dependency graph for visualization.
        Returns nodes (rules + fields) and edges (dependency links).
        """
        rules = db.query(DetectionRule).all()
        deps = db.query(DetectionRuleDependency).all()

        nodes = []
        edges = []
        field_set = set()

        for rule in rules:
            nodes.append({
                "id": rule.rule_id,
                "label": rule.rule_name,
                "type": "rule",
                "severity": rule.severity,
                "status": rule.status,
            })

        for dep in deps:
            field_set.add(dep.canonical_field)
            edges.append({
                "source": dep.rule_id,
                "target": f"field_{dep.canonical_field}",
                "dependency_type": dep.dependency_type,
            })

        for field_name in field_set:
            nodes.append({
                "id": f"field_{field_name}",
                "label": field_name,
                "type": "field",
                "severity": None,
                "status": None,
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "total_rules": len(rules),
            "total_fields": len(field_set),
        }

    @staticmethod
    def get_canonical_fields() -> List[str]:
        """Return the known canonical field names from NormalizedEvent."""
        return sorted(CANONICAL_FIELDS)

    @staticmethod
    def add_dependency(
        db: Session,
        rule_id: str,
        canonical_field: str,
        dependency_type: str = "REQUIRED",
        description: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Add a canonical field dependency to an existing detection rule."""
        rule = (
            db.query(DetectionRule)
            .filter(DetectionRule.rule_id == rule_id)
            .first()
        )
        if not rule:
            return None

        # Check for duplicate
        existing = (
            db.query(DetectionRuleDependency)
            .filter(
                DetectionRuleDependency.rule_id == rule_id,
                DetectionRuleDependency.canonical_field == canonical_field,
            )
            .first()
        )
        if existing:
            return existing.to_dict()

        dep = DetectionRuleDependency(
            dependency_id=f"ddep_{uuid.uuid4().hex[:12]}",
            rule_id=rule_id,
            canonical_field=canonical_field,
            dependency_type=dependency_type.upper() if dependency_type else "REQUIRED",
            description=description,
        )
        db.add(dep)
        db.commit()
        db.refresh(dep)
        logger.info("Added dependency: %s -> %s (%s)", rule_id, canonical_field, dependency_type)
        return dep.to_dict()
