"""
services/threat_indicator_service.py
-----------------------------------
IOC Extraction, Canonical Normalization, Validation, and Hashing Service.

Sprint 11B — Threat Intelligence Integration, Adversary Context & Security Intelligence Correlation.
"""

from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
from sqlalchemy.orm import Session

from app.models.threat_intelligence import (
    ThreatIndicator,
    INDICATOR_DOMAIN_PREFIX,
    compute_canonical_hash,
)
from app.services.governance_ledger_service import GovernanceLedgerService


def to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class ThreatIndicatorService:
    """
    Handles IOC canonical normalization, validation, and registry management.
    """

    @staticmethod
    def normalize_indicator(indicator_type: str, indicator_value: str) -> Tuple[str, str]:
        """
        Validates and canonicalizes IOC value based on type.
        Returns: (normalized_type, normalized_value)
        Raises: ValueError on validation failure.
        """
        if not indicator_value or not indicator_value.strip():
            raise ValueError("Indicator value cannot be empty.")

        val = indicator_value.strip()
        itype = indicator_type.upper().strip()

        if itype in ("IP", "IP_ADDRESS", "IPV4", "IPV6"):
            norm_type = "IP_ADDRESS"
            try:
                ip_obj = ipaddress.ip_address(val)
                norm_val = str(ip_obj)
            except ValueError as e:
                raise ValueError(f"Invalid IP address observable '{val}': {e}")

        elif itype in ("DOMAIN", "FQDN"):
            norm_type = "DOMAIN"
            cleaned = val.lower()
            if cleaned.startswith("http://") or cleaned.startswith("https://"):
                parsed = urllib.parse.urlparse(cleaned)
                cleaned = parsed.netloc or parsed.path
            cleaned = cleaned.rstrip("/")
            if cleaned.startswith("www."):
                cleaned = cleaned[4:]
            if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", cleaned):
                raise ValueError(f"Invalid domain format '{val}'.")
            norm_val = cleaned

        elif itype in ("URL", "URI"):
            norm_type = "URL"
            try:
                parsed = urllib.parse.urlparse(val)
                scheme = parsed.scheme.lower() if parsed.scheme else "http"
                netloc = parsed.netloc.lower() if parsed.netloc else ""
                path = parsed.path.rstrip("/") if parsed.path else ""
                norm_val = urllib.parse.urlunparse((scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))
                if not netloc:
                    raise ValueError("URL must contain a valid network location/host.")
            except Exception as e:
                raise ValueError(f"Invalid URL observable '{val}': {e}")

        elif itype in ("FILE_HASH", "HASH", "SHA256", "MD5", "SHA1"):
            norm_type = "FILE_HASH"
            cleaned = val.lower().strip()
            if not re.match(r"^[a-f0-9]+$", cleaned) or len(cleaned) not in (32, 40, 64):
                raise ValueError(f"Invalid file hash '{val}'. Must be valid 32/40/64 hex characters (MD5/SHA1/SHA256).")
            norm_val = cleaned

        elif itype in ("EMAIL", "EMAIL_ADDRESS"):
            norm_type = "EMAIL_ADDRESS"
            cleaned = val.lower().strip()
            if not re.match(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$", cleaned):
                raise ValueError(f"Invalid email address observable '{val}'.")
            norm_val = cleaned

        elif itype in ("HOSTNAME", "HOST"):
            norm_type = "HOSTNAME"
            cleaned = val.lower().strip()
            if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", cleaned):
                raise ValueError(f"Invalid hostname format '{val}'.")
            norm_val = cleaned

        else:
            raise ValueError(f"Unsupported indicator type '{indicator_type}'.")

        return norm_type, norm_val

    @staticmethod
    def register_indicator(
        db: Session,
        indicator_value: str,
        indicator_type: str,
        artifact_id: Optional[str] = None,
        confidence_score: float = 100.0,
        severity: str = "MEDIUM",
        expires_at: Optional[datetime] = None,
        actor_user_id: str = "SYSTEM",
    ) -> ThreatIndicator:
        norm_type, norm_val = ThreatIndicatorService.normalize_indicator(indicator_type, indicator_value)

        # Check existing indicator for duplicate handling
        existing = db.query(ThreatIndicator).filter(
            ThreatIndicator.indicator_type == norm_type,
            ThreatIndicator.normalized_value == norm_val,
        ).first()

        now = datetime.now(timezone.utc)

        if existing:
            # Update last_seen and status
            existing.last_seen = now
            existing.confidence_score = confidence_score
            existing.severity = severity
            if expires_at:
                existing.expires_at = expires_at
            exp_utc = to_utc(existing.expires_at)
            if exp_utc and exp_utc < now:
                existing.status = "EXPIRED"
                existing.is_active = False
            else:
                existing.status = "ACTIVE"
                existing.is_active = True
            existing.indicator_hash = existing.compute_indicator_hash()
            db.flush()
            return existing

        status = "ACTIVE"
        is_active = True
        exp_new_utc = to_utc(expires_at)
        if exp_new_utc and exp_new_utc < now:
            status = "EXPIRED"
            is_active = False

        indicator = ThreatIndicator(
            indicator_value=indicator_value.strip(),
            indicator_type=norm_type,
            normalized_value=norm_val,
            artifact_id=artifact_id,
            confidence_score=max(0.0, min(100.0, confidence_score)),
            severity=severity.upper(),
            status=status,
            first_seen=now,
            last_seen=now,
            expires_at=expires_at,
            is_active=is_active,
            indicator_hash="",
        )
        indicator.indicator_hash = indicator.compute_indicator_hash()

        db.add(indicator)
        db.flush()

        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="THREAT_INDICATOR_REGISTERED",
                actor_user_id=actor_user_id,
                details={
                    "indicator_id": indicator.id,
                    "indicator_type": norm_type,
                    "normalized_value": norm_val,
                    "severity": indicator.severity,
                    "status": indicator.status,
                    "indicator_hash": indicator.indicator_hash,
                },
            )
        except Exception:
            pass

        return indicator
