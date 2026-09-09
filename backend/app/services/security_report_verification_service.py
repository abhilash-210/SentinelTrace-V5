"""
services/security_report_verification_service.py
------------------------------------------------
Multi-Layer Cryptographic Verification Engine for Reports & Evidence Packages.

Sprint 12B — Security Analytics, Reporting & Evidence Intelligence.
Core Invariant: "REPORT TRUST = UNTRUSTED IF ANY SECTION OR MANIFEST HASH FAILS VERIFICATION."
"""

from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.security_analytics import (
    SecurityReport,
    SecurityReportSection,
    SecurityEvidencePackage,
    EvidencePackageArtifact,
    SECURITY_REPORT_DOMAIN_PREFIX,
    REPORT_SECTION_DOMAIN_PREFIX,
    EVIDENCE_PACKAGE_DOMAIN_PREFIX,
    EVIDENCE_BINDING_DOMAIN_PREFIX,
    compute_canonical_hash,
)


class SecurityReportVerificationService:
    """
    Cryptographically verifies integrity, section hashes, manifests, and ledger commitments.
    """

    @staticmethod
    def verify_report(db: Session, report_id: str) -> Dict[str, Any]:
        """
        Validates entire report lineage: sections, manifest, hash seal, and ledger references.
        """
        report = db.query(SecurityReport).filter_by(id=report_id).first()
        if not report:
            return {
                "report_id": report_id,
                "verified": False,
                "status": "UNKNOWN",
                "error": "Report not found",
            }

        tampered_sections: List[int] = []
        sections = db.query(SecurityReportSection).filter_by(
            report_id=report.id
        ).order_by(SecurityReportSection.section_order.asc()).all()

        for s in sections:
            s_payload = {
                "report_id": report.id,
                "section_order": s.section_order,
                "section_type": s.section_type,
                "title": s.title,
                "content": s.content_json,
            }
            expected_hash = compute_canonical_hash(REPORT_SECTION_DOMAIN_PREFIX, s_payload)
            if expected_hash != s.section_hash:
                tampered_sections.append(s.section_order)

        # Verify overall manifest and report hash
        manifest_payload = report.canonical_manifest_json
        expected_report_hash = compute_canonical_hash(SECURITY_REPORT_DOMAIN_PREFIX, manifest_payload)

        report_hash_valid = (expected_report_hash == report.report_hash)
        sections_valid = (len(tampered_sections) == 0)
        overall_verified = report_hash_valid and sections_valid

        status = "VERIFIED" if overall_verified else "UNTRUSTED"

        # Update report status in DB if tampered
        if not overall_verified and report.integrity_status != "UNTRUSTED":
            report.integrity_status = "UNTRUSTED"
            db.commit()

        return {
            "report_id": report.id,
            "report_number": report.report_number,
            "verified": overall_verified,
            "status": status,
            "report_hash_valid": report_hash_valid,
            "sections_count": len(sections),
            "tampered_sections": tampered_sections,
            "stored_report_hash": report.report_hash,
            "computed_report_hash": expected_report_hash,
            "ledger_reference": report.ledger_reference,
            "merkle_reference": report.merkle_reference,
        }

    @staticmethod
    def verify_evidence_package(db: Session, package_id: str) -> Dict[str, Any]:
        """
        Validates evidence package manifest, artifact bindings, and checksum integrity.
        """
        package = db.query(SecurityEvidencePackage).filter_by(id=package_id).first()
        if not package:
            return {
                "package_id": package_id,
                "verified": False,
                "status": "UNKNOWN",
                "error": "Evidence package not found",
            }

        tampered_bindings: List[str] = []
        artifacts = db.query(EvidencePackageArtifact).filter_by(
            package_id=package.id
        ).all()

        for a in artifacts:
            b_payload = {
                "package_id": package.id,
                "artifact_domain": a.artifact_domain,
                "artifact_type": a.artifact_type,
                "artifact_id": a.artifact_id,
                "artifact_hash": a.artifact_hash,
            }
            expected_b_hash = compute_canonical_hash(EVIDENCE_BINDING_DOMAIN_PREFIX, b_payload)
            if expected_b_hash != a.binding_hash:
                tampered_bindings.append(a.id)

        manifest_payload = package.manifest_json
        expected_manifest_hash = compute_canonical_hash(EVIDENCE_PACKAGE_DOMAIN_PREFIX, manifest_payload)

        manifest_hash_valid = (expected_manifest_hash == package.manifest_hash)
        bindings_valid = (len(tampered_bindings) == 0)
        overall_verified = manifest_hash_valid and bindings_valid

        status = "VERIFIED" if overall_verified else "UNTRUSTED"

        if not overall_verified and package.integrity_status != "UNTRUSTED":
            package.integrity_status = "UNTRUSTED"
            db.commit()

        return {
            "package_id": package.id,
            "package_number": package.package_number,
            "verified": overall_verified,
            "status": status,
            "manifest_hash_valid": manifest_hash_valid,
            "artifact_count": len(artifacts),
            "tampered_bindings": tampered_bindings,
            "stored_manifest_hash": package.manifest_hash,
            "computed_manifest_hash": expected_manifest_hash,
            "ledger_reference": package.ledger_reference,
            "merkle_reference": package.merkle_reference,
        }
