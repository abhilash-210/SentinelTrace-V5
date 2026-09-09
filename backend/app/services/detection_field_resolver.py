"""
services/detection_field_resolver.py
-------------------------------------
Canonical Field Resolution Engine for the SentinelTrace Detection Engine.

Sprint 7A — Real-Time Detection Rule Execution Engine.

Purpose:
Safely and deterministically resolve canonical fields and aliases from
OCSF-aligned normalized security events (NormalizedEvent).

Architectural Principles:
- The resolver must NEVER guess or fabricate values.
- If a canonical field or alias is unavailable or empty in the normalized event,
  return an explicit MISSING state: `{"field": "...", "resolved": False, "value": None}`.
- Supports dot-notation paths, canonical field aliases, and raw_data inspection.
- Preserves exact data types where applicable (e.g. Integer ports, string values).
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import logging

from app.models.normalized_event import NormalizedEvent

logger = logging.getLogger("sentinel.services.detection_field_resolver")


@dataclass(frozen=True)
class FieldResolutionResult:
    """Immutable result of resolving a canonical field from a normalized event."""
    field: str
    resolved: bool
    value: Any

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "resolved": self.resolved,
            "value": self.value,
        }


class DetectionFieldResolver:
    """
    Deterministic field resolution engine for detection rule execution.
    Maps canonical DSL field names and known aliases to normalized event attributes.
    """

    # Explicit Canonical Alias Map to model attribute names
    ALIAS_MAP: Dict[str, List[str]] = {
        "action.result": ["action", "disposition", "action.result", "act"],
        "disposition": ["action", "disposition"],
        "action": ["action"],
        "src_endpoint_ip": ["src_ip", "src_endpoint_ip", "source_ip", "src_endpoint.ip"],
        "src_endpoint.ip": ["src_ip", "src_endpoint_ip", "source_ip", "src_endpoint.ip"],
        "src_ip": ["src_ip", "source_ip"],
        "dst_endpoint_ip": ["dst_ip", "dst_endpoint_ip", "dest_ip", "destination_ip", "dst_endpoint.ip"],
        "dst_endpoint.ip": ["dst_ip", "dst_endpoint_ip", "dest_ip", "destination_ip", "dst_endpoint.ip"],
        "dst_ip": ["dst_ip", "dest_ip", "destination_ip"],
        "src_endpoint.port": ["src_port", "src_endpoint_port", "source_port", "src_endpoint.port"],
        "src_endpoint_port": ["src_port", "src_endpoint_port", "source_port", "src_endpoint.port"],
        "src_port": ["src_port", "source_port"],
        "dst_endpoint.port": ["dst_port", "dst_endpoint_port", "dest_port", "destination_port", "dst_endpoint.port"],
        "dst_endpoint_port": ["dst_port", "dst_endpoint_port", "dest_port", "destination_port", "dst_endpoint.port"],
        "dst_port": ["dst_port", "dest_port", "destination_port"],
        "protocol": ["protocol", "network_protocol"],
        "severity": ["severity"],
        "user_name": ["user_name", "user", "username", "account_name"],
        "user": ["user_name", "user", "username"],
        "username": ["user_name", "user", "username"],
        "hostname": ["hostname", "host", "device_name", "endpoint_name"],
        "host": ["hostname", "host"],
        "process_name": ["process_name", "process", "image_name", "exe"],
        "process": ["process_name", "process"],
        "process_id": ["process_id", "pid"],
        "pid": ["process_id", "pid"],
        "event_type": ["class_name", "activity_name", "event_type"],
        "class_name": ["class_name"],
        "class_uid": ["class_uid"],
        "activity_name": ["activity_name"],
        "activity_id": ["activity_id"],
        "source_name": ["source_name"],
        "source_type": ["source_type"],
        "event_time": ["event_time"],
    }

    @classmethod
    def resolve(cls, event: NormalizedEvent, field_path: str) -> FieldResolutionResult:
        """
        Resolve a canonical field name or alias path against a NormalizedEvent instance.

        Returns FieldResolutionResult with:
          - resolved = True and value = <val> if field exists and is non-None
          - resolved = False and value = None if field is missing or None
        """
        if not field_path:
            return FieldResolutionResult(field="", resolved=False, value=None)

        clean_path = field_path.strip()
        lower_path = clean_path.lower()

        # Special handling for authentication.outcome
        if lower_path in ("authentication.outcome", "auth.outcome", "authentication_outcome"):
            return cls._resolve_authentication_outcome(event, clean_path)

        # 1. Check known alias mappings against normalized model attributes
        aliases = cls.ALIAS_MAP.get(lower_path, [lower_path])
        for alias in aliases:
            # Check model direct attribute
            attr_name = alias.replace(".", "_")
            if hasattr(event, attr_name):
                val = getattr(event, attr_name)
                if val is not None and val != "":
                    # If string, clean or preserve
                    return FieldResolutionResult(field=clean_path, resolved=True, value=val)

            if hasattr(event, alias):
                val = getattr(event, alias)
                if val is not None and val != "":
                    return FieldResolutionResult(field=clean_path, resolved=True, value=val)

        # 2. Check raw_data dictionary for direct key or nested path
        raw_data = event.raw_data if isinstance(event.raw_data, dict) else {}
        val_from_raw = cls._extract_from_dict(raw_data, clean_path)
        if val_from_raw is not None and val_from_raw != "":
            return FieldResolutionResult(field=clean_path, resolved=True, value=val_from_raw)

        # Also check aliases in raw_data
        for alias in aliases:
            val = cls._extract_from_dict(raw_data, alias)
            if val is not None and val != "":
                return FieldResolutionResult(field=clean_path, resolved=True, value=val)

        # Explicit missing state
        return FieldResolutionResult(field=clean_path, resolved=False, value=None)

    @classmethod
    def _resolve_authentication_outcome(cls, event: NormalizedEvent, field_path: str) -> FieldResolutionResult:
        """
        Safely resolve authentication outcome.
        Only resolves if the event is an authentication event or contains explicit outcome telemetry.
        Never fabricates auth outcome for firewall or unrelated traffic.
        """
        raw_data = event.raw_data if isinstance(event.raw_data, dict) else {}

        # 1. Direct explicit auth outcome in raw data
        for key in ["authentication.outcome", "auth_outcome", "outcome", "logon_result", "login_status"]:
            if key in raw_data and raw_data[key] is not None and raw_data[key] != "":
                return FieldResolutionResult(field=field_path, resolved=True, value=str(raw_data[key]).upper())

        # 2. Check if event is an Authentication class event
        is_auth_event = (
            (event.class_name and "auth" in event.class_name.lower())
            or (event.source_type and "auth" in event.source_type.lower())
            or (event.class_uid == 3001)
        )

        if is_auth_event:
            # If normalized action is available (e.g. SUCCESS, FAILURE, ALLOW, DENY)
            if event.action:
                act = str(event.action).upper()
                if act in ("SUCCESS", "FAILURE", "ALLOW", "ALLOWED", "DENY", "DENIED"):
                    # Map ALLOW -> SUCCESS, DENY -> FAILURE if standard auth
                    mapped = "SUCCESS" if act in ("SUCCESS", "ALLOW", "ALLOWED") else "FAILURE"
                    return FieldResolutionResult(field=field_path, resolved=True, value=mapped)
                return FieldResolutionResult(field=field_path, resolved=True, value=act)

            if event.activity_name:
                act_name = event.activity_name.upper()
                if "FAILURE" in act_name or "FAIL" in act_name or "DENIED" in act_name:
                    return FieldResolutionResult(field=field_path, resolved=True, value="FAILURE")
                if "SUCCESS" in act_name or "LOGON" in act_name:
                    return FieldResolutionResult(field=field_path, resolved=True, value="SUCCESS")

        # Not an authentication event and no auth telemetry present -> MISSING
        return FieldResolutionResult(field=field_path, resolved=False, value=None)

    @staticmethod
    def _extract_from_dict(d: Dict[str, Any], key_path: str) -> Optional[Any]:
        """Extract a value from nested dict supporting dot notation and direct lookup."""
        if not isinstance(d, dict) or not key_path:
            return None

        # Direct key lookup
        if key_path in d:
            return d[key_path]

        # Case-insensitive direct lookup
        for k, v in d.items():
            if k.lower() == key_path.lower():
                return v

        # Nested path traversal (e.g. "dst_endpoint.port")
        if "." in key_path:
            parts = key_path.split(".")
            curr = d
            for part in parts:
                if isinstance(curr, dict):
                    found = False
                    for k, v in curr.items():
                        if k.lower() == part.lower():
                            curr = v
                            found = True
                            break
                    if not found:
                        return None
                else:
                    return None
            return curr

        return None
