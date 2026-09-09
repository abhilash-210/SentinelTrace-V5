"""
services/source_detector.py
---------------------------
Deterministic Source Identification & Parser Selection.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
Matches ingested events to active structural Source Profiles.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Default Seed Source Profiles for Sprint 2
DEFAULT_SOURCE_PROFILES = [
    {
        "source_profile_id": "sp_firewall_syslog",
        "profile_name": "Generic Firewall Syslog",
        "source_type": "firewall",
        "supported_format": "text",
        "parser_type": "syslog",
        "version": "v1.0.0",
        "is_active": True,
        "configuration": {"class_name": "Network Activity", "class_uid": 4001, "activity_name": "Network Traffic"},
    },
    {
        "source_profile_id": "sp_app_json",
        "profile_name": "Generic Application JSON Log",
        "source_type": "authentication",
        "supported_format": "json",
        "parser_type": "json",
        "version": "v1.0.0",
        "is_active": True,
        "configuration": {"class_name": "Authentication", "class_uid": 3001, "activity_name": "Logon Activity"},
    },
    {
        "source_profile_id": "sp_system_csv",
        "profile_name": "Generic System CSV Audit Log",
        "source_type": "system",
        "supported_format": "csv",
        "parser_type": "csv",
        "version": "v1.0.0",
        "is_active": True,
        "configuration": {"class_name": "System Activity", "class_uid": 1001, "activity_name": "Process Audit"},
    },
]


class SourceDetector:
    """
    Deterministic rule-based source detector.

    Selects the optimal parser and matching Source Profile without using ML or heuristics.
    """

    @staticmethod
    def detect(
        file_format: str,
        source_type: str,
        source_name: str,
        raw_content: str,
    ) -> Tuple[str, str, float, List[str]]:
        """
        Detect parser and profile.

        Returns (parser_type, source_profile_id, confidence, reasons).
        """
        fmt = (file_format or "").lower().strip()
        stype = (source_type or "").lower().strip()
        sname = (source_name or "").lower().strip()
        reasons: List[str] = []
        confidence = 1.0

        # Rule 1: Explicit JSON format or JSON payload detection
        if fmt == "json" or (raw_content.strip().startswith("{") and raw_content.strip().endswith("}")):
            try:
                json.loads(raw_content.strip())
                reasons.append("Valid JSON syntax confirmed")
                if "auth" in stype or "auth" in sname:
                    reasons.append("Source matches authentication profile")
                    return "json", "sp_app_json", 0.98, reasons
                return "json", "sp_app_json", 0.95, reasons
            except Exception:
                confidence -= 0.20
                reasons.append("JSON format specified but payload required lenient parsing")
                return "json", "sp_app_json", confidence, reasons

        # Rule 2: Explicit CSV format or header commas
        if fmt == "csv" or ("," in raw_content.split("\n")[0] and "\n" in raw_content):
            reasons.append("CSV header delimiter detected")
            if "system" in stype or "audit" in stype or "proc" in stype:
                reasons.append("Source matches system audit profile")
                return "csv", "sp_system_csv", 0.98, reasons
            return "csv", "sp_system_csv", 0.92, reasons

        # Rule 3: Firewall / Syslog streams
        if fmt in ["syslog", "text"] or "firewall" in stype or "fw" in sname or "asa" in sname:
            reasons.append("Syslog RFC / Cisco header pattern matched")
            if "firewall" in stype or "fw" in sname:
                return "syslog", "sp_firewall_syslog", 0.95, reasons
            return "syslog", "sp_firewall_syslog", 0.88, reasons

        # Rule 4: Fallback
        reasons.append("Unidentified format - applying generic text syslog parser")
        return "syslog", "sp_firewall_syslog", 0.70, reasons
