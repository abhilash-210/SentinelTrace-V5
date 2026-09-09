"""
parsers/json_parser.py
----------------------
Deterministic JSON Parser for structured security events (authentication, cloud, audit).

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.parsers.base_parser import BaseParser


class JSONParser(BaseParser):
    """
    Parser for structured JSON security events.
    """

    name = "JSONParser"
    version = "1.0.0"
    supported_formats = ["json"]

    def parse(self, raw_content: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Safely parse structured JSON payload without throwing exceptions."""
        if not raw_content or not isinstance(raw_content, str):
            return {
                "success": False,
                "fields": {},
                "error": "Empty raw content provided to JSONParser",
                "timestamp": None,
                "confidence_deductions": ["empty content"],
            }

        deductions: List[str] = []
        parsed_time: Optional[datetime] = None

        try:
            data = json.loads(raw_content.strip())
        except Exception as exc:
            return {
                "success": False,
                "fields": {},
                "error": f"JSON syntax error: {str(exc)}",
                "timestamp": None,
                "confidence_deductions": ["invalid JSON syntax"],
            }

        if not isinstance(data, dict):
            return {
                "success": False,
                "fields": {"raw_array": data},
                "error": "JSON payload is not a JSON object",
                "timestamp": None,
                "confidence_deductions": ["JSON root is not an object"],
            }

        fields: Dict[str, Any] = dict(data)

        # 1. Timestamp extraction
        time_field = data.get("timestamp") or data.get("@timestamp") or data.get("time") or data.get("event_time")
        if time_field:
            fields["raw_timestamp"] = str(time_field)
            try:
                clean_iso = str(time_field).replace("Z", "+00:00")
                parsed_time = datetime.fromisoformat(clean_iso)
            except Exception:
                deductions.append("timestamp unparseable ISO format")
        else:
            deductions.append("timestamp missing in JSON payload")

        # 2. Canonical Action / Event Type
        event_type = data.get("event_type") or data.get("action") or data.get("event") or data.get("status")
        if event_type:
            upper_event = str(event_type).upper()
            if "FAIL" in upper_event or "DENY" in upper_event or "ERROR" in upper_event:
                fields["action"] = "FAILURE"
            elif "SUCCESS" in upper_event or "ALLOW" in upper_event or "LOGIN" in upper_event:
                fields["action"] = "SUCCESS"
            else:
                fields["action"] = str(event_type)
        else:
            fields["action"] = None
            deductions.append("action/event_type field missing")

        # 3. Source IP / Client IP
        src_ip = data.get("client_ip") or data.get("src_ip") or data.get("source_ip") or data.get("ip")
        if src_ip:
            fields["src_ip"] = str(src_ip)
        else:
            fields["src_ip"] = None

        # 4. User / Actor
        user = data.get("username") or data.get("user") or data.get("account") or data.get("actor")
        if user:
            fields["user_name"] = str(user)
        else:
            fields["user_name"] = None

        # 5. Service / Application
        service = data.get("service") or data.get("application") or data.get("app_name")
        if service:
            fields["app_name"] = str(service)

        return {
            "success": True,
            "fields": fields,
            "error": None,
            "timestamp": parsed_time,
            "confidence_deductions": deductions,
        }
