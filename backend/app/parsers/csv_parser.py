"""
parsers/csv_parser.py
---------------------
Deterministic CSV Parser for tabular system and endpoint security audit events.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
"""

import csv
import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.parsers.base_parser import BaseParser


class CSVParser(BaseParser):
    """
    Parser for comma-separated value (CSV) security audit records.
    """

    name = "CSVParser"
    version = "1.0.0"
    supported_formats = ["csv"]

    def parse(self, raw_content: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Safely parse CSV payload into structured dictionary."""
        if not raw_content or not isinstance(raw_content, str):
            return {
                "success": False,
                "fields": {},
                "error": "Empty raw content provided to CSVParser",
                "timestamp": None,
                "confidence_deductions": ["empty content"],
            }

        deductions: List[str] = []
        parsed_time: Optional[datetime] = None

        lines = [line.strip() for line in raw_content.strip().split("\n") if line.strip()]
        if not lines:
            return {
                "success": False,
                "fields": {},
                "error": "No non-empty lines in CSV",
                "timestamp": None,
                "confidence_deductions": ["no data lines in CSV"],
            }

        try:
            reader = csv.DictReader(io.StringIO(raw_content.strip()))
            rows = list(reader)
            if not rows or not reader.fieldnames:
                # Handle single row without header if necessary
                return {
                    "success": False,
                    "fields": {},
                    "error": "Unable to extract CSV headers or records",
                    "timestamp": None,
                    "confidence_deductions": ["missing CSV header"],
                }
            
            # Extract first data row
            row = rows[0]
        except Exception as exc:
            return {
                "success": False,
                "fields": {},
                "error": f"CSV parse error: {str(exc)}",
                "timestamp": None,
                "confidence_deductions": ["malformed CSV syntax"],
            }

        # Normalize column key names (lowercase stripped)
        normalized_row: Dict[str, Any] = {k.strip().lower(): v.strip() for k, v in row.items() if k}

        fields: Dict[str, Any] = dict(normalized_row)

        # 1. Timestamp extraction
        time_str = (
            normalized_row.get("timestamp")
            or normalized_row.get("time")
            or normalized_row.get("datetime")
            or normalized_row.get("date")
        )
        if time_str:
            fields["raw_timestamp"] = time_str
            try:
                clean_iso = time_str.replace("Z", "+00:00")
                parsed_time = datetime.fromisoformat(clean_iso)
            except Exception:
                deductions.append("timestamp unparseable in CSV")
        else:
            deductions.append("timestamp column missing in CSV")

        # 2. Hostname
        host = normalized_row.get("hostname") or normalized_row.get("host") or normalized_row.get("endpoint")
        if host:
            fields["hostname"] = host

        # 3. Process fields
        proc = normalized_row.get("process_name") or normalized_row.get("process") or normalized_row.get("command")
        if proc:
            fields["process_name"] = proc

        pid_str = normalized_row.get("process_id") or normalized_row.get("pid")
        if pid_str:
            try:
                fields["process_id"] = int(pid_str)
            except Exception:
                fields["process_id"] = None
                deductions.append("process_id non-numeric")

        # 4. User
        user = normalized_row.get("user") or normalized_row.get("username") or normalized_row.get("actor")
        if user:
            fields["user_name"] = user

        # 5. Action / Status
        action = normalized_row.get("action") or normalized_row.get("event") or normalized_row.get("status")
        if action:
            upper_act = action.upper()
            if "SUCCESS" in upper_act or "ALLOW" in upper_act or "EXEC" in upper_act:
                fields["action"] = "SUCCESS"
            elif "FAIL" in upper_act or "DENY" in upper_act:
                fields["action"] = "FAILURE"
            else:
                fields["action"] = action
        else:
            fields["action"] = None
            deductions.append("action column missing in CSV")

        return {
            "success": True,
            "fields": fields,
            "error": None,
            "timestamp": parsed_time,
            "confidence_deductions": deductions,
        }
