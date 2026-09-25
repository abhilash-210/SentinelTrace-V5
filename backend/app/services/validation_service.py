import ipaddress
from typing import Any, Dict, List, Optional
from app.models.normalized_event import NormalizedEvent

class EventValidationException(Exception):
    """Exception raised when a normalized event fails structural or schema validation."""
    def __init__(self, validation_result: Dict[str, Any]):
        self.validation_result = validation_result
        super().__init__("Event validation failed")


class ValidationService:
    """
    Dedicated engine for validating OCSF-aligned normalized events
    before they are considered successfully processed.
    """

    @staticmethod
    def validate_normalized_event(event: NormalizedEvent) -> Dict[str, Any]:
        """
        Deterministically validate the event.
        Returns a structured dictionary indicating validity and failure reasons.
        """
        reasons: List[str] = []
        failed_fields: List[str] = []

        # 1. Required fields
        if not getattr(event, "original_event_id", None):
            reasons.append("Missing required field: original_event_id")
            failed_fields.append("original_event_id")

        if not getattr(event, "class_name", None):
            reasons.append("Missing required field: class_name")
            failed_fields.append("class_name")

        # 2. Timestamp validity
        if not getattr(event, "event_time", None):
            reasons.append("Missing or invalid event_time")
            failed_fields.append("event_time")

        # 3. IP Address structure validation
        for ip_field in ["src_ip", "dst_ip"]:
            ip_val = getattr(event, ip_field, None)
            if ip_val:
                try:
                    ipaddress.ip_address(ip_val)
                except ValueError:
                    reasons.append(f"Invalid IP address structure in {ip_field}")
                    failed_fields.append(ip_field)

        # 4. Port structure validation
        for port_field in ["src_port", "dst_port"]:
            port_val = getattr(event, port_field, None)
            if port_val is not None:
                # In SQLite it might be parsed as str if parser returned str, but model expects int
                try:
                    port_int = int(port_val)
                    if not (0 <= port_int <= 65535):
                        raise ValueError()
                except (ValueError, TypeError):
                    reasons.append(f"Invalid port value in {port_field} (must be 0-65535)")
                    failed_fields.append(port_field)

        # 5. OCSF Category Validation
        valid_classes = {"Network Activity", "Authentication", "System Activity"}
        class_name = getattr(event, "class_name", None)
        if class_name and class_name not in valid_classes:
            reasons.append(f"Invalid OCSF class_name: {class_name}")
            failed_fields.append("class_name")

        if reasons:
            return {
                "valid": False,
                "failure_stage": "NORMALIZATION_VALIDATION",
                "reason_code": "VALIDATION_FAILED",
                "message": "; ".join(reasons),
                "field": failed_fields[0] if failed_fields else "unknown"
            }

        return {
            "valid": True,
            "failure_stage": None,
            "reason_code": "OK",
            "message": "Event is fully valid and OCSF-compliant",
            "field": None
        }

    @staticmethod
    def enforce_validation(event: NormalizedEvent) -> None:
        """
        Validates the event and raises EventValidationException if it fails.
        """
        result = ValidationService.validate_normalized_event(event)
        if not result["valid"]:
            raise EventValidationException(result)
