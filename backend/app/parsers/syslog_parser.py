"""
parsers/syslog_parser.py
------------------------
Deterministic Syslog Parser for Cisco ASA, RFC 5424, and RFC 3164 security events.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.parsers.base_parser import BaseParser


class SyslogParser(BaseParser):
    """
    Parser for extracting network, timestamp, host, and action fields from Syslog streams.
    """

    name = "SyslogParser"
    version = "1.0.0"
    supported_formats = ["text", "syslog"]

    # Cisco ASA connection pattern:
    # Built/Teardown inbound/outbound TCP/UDP connection ... for outside:1.2.3.4/443 to inside:5.6.7.8/1234
    _ASA_CONN_PATTERN = re.compile(
        r"(?:Built|Teardown|Deny)\s+(?:inbound|outbound)?\s*(TCP|UDP|ICMP)?\s*(?:connection)?\s*(\d+)?\s*"
        r"(?:for\s+)?(?:outside|inside|\w+):([0-9a-fA-F\.:]+)/(\d+)\s*"
        r"(?:(?:\([^\)]+\)\s*)?to\s+(?:inside|outside|\w+):([0-9a-fA-F\.:]+)/(\d+))?",
        re.IGNORECASE,
    )

    # General IP:port or IP/port pattern
    _IP_PORT_PATTERN = re.compile(
        r"(?:src(?:_ip)?|from)\s*[:=]\s*([0-9a-fA-F\.:]+)(?:[:/](\d+))?.*?"
        r"(?:dst(?:_ip)?|to)\s*[:=]\s*([0-9a-fA-F\.:]+)(?:[:/](\d+))?",
        re.IGNORECASE,
    )

    # RFC 5424 header: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
    _RFC5424_PATTERN = re.compile(
        r"^<(\d{1,3})>(?:(\d+)\s+)?(\d{4}-\d{2}-\d{2}T[\d:\.]+Z?|\w{3}\s+\d+\s+[\d:]+)\s+([^\s]+)\s+([^\s]+)?\s*([^\s]+)?\s*(.*)$"
    )

    # Priority to severity mapping
    _SEVERITY_MAP = {
        0: "Emergency",
        1: "Alert",
        2: "Critical",
        3: "Error",
        4: "Warning",
        5: "Notice",
        6: "Informational",
        7: "Debug",
    }

    def parse(self, raw_content: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Parse raw syslog text safely without throwing unhandled exceptions."""
        if not raw_content or not isinstance(raw_content, str):
            return {
                "success": False,
                "fields": {},
                "error": "Empty or non-string raw content provided to SyslogParser",
                "timestamp": None,
                "confidence_deductions": ["empty content"],
            }

        fields: Dict[str, Any] = {}
        deductions: List[str] = []
        parsed_time: Optional[datetime] = None

        line = raw_content.strip().split("\n")[0]  # Focus on first event line

        # 1. Header parsing (PRI, timestamp, hostname)
        header_match = self._RFC5424_PATTERN.match(line)
        msg_body = line

        if header_match:
            pri = int(header_match.group(1))
            fields["priority"] = pri
            fields["severity"] = self._SEVERITY_MAP.get(pri % 8, "Informational")
            time_str = header_match.group(3)
            fields["raw_timestamp"] = time_str
            fields["hostname"] = header_match.group(4)
            if header_match.group(5):
                fields["app_name"] = header_match.group(5)
            if header_match.group(7):
                msg_body = header_match.group(7)
            else:
                msg_body = line

            # Attempt timestamp parse
            try:
                if "T" in time_str:
                    clean_iso = time_str.replace("Z", "+00:00")
                    parsed_time = datetime.fromisoformat(clean_iso)
                else:
                    # e.g., Sep 06 12:34:56
                    current_year = datetime.now(timezone.utc).year
                    parsed_time = datetime.strptime(f"{current_year} {time_str}", "%Y %b %d %H:%M:%S").replace(
                        tzinfo=timezone.utc
                    )
            except Exception:
                deductions.append("timestamp unparseable")
        else:
            deductions.append("syslog header non-standard")

        # 2. Action extraction
        upper_body = msg_body.upper()
        action_match = re.search(r"\baction=([a-zA-Z0-9_-]+)", msg_body, re.IGNORECASE)
        if action_match:
            fields["action"] = action_match.group(1).upper()
        else:
            if " BUILT " in upper_body or "ACCEPTED" in upper_body or "ALLOW" in upper_body:
                fields["action"] = "ALLOW"
            elif "ACTION=DENY" in upper_body or " DENY " in upper_body or "DROP" in upper_body or "BLOCKED" in upper_body:
                fields["action"] = "DENY"
            elif "TEARDOWN" in upper_body or "CLOSED" in upper_body:
                fields["action"] = "CLOSE"
            else:
                fields["action"] = None
                deductions.append("action not explicitly identified")

        # 3. Network Connection Fields (Cisco ASA / IP extraction)
        asa_match = self._ASA_CONN_PATTERN.search(msg_body)
        if asa_match:
            if asa_match.group(1):
                fields["protocol"] = asa_match.group(1).upper()
            if asa_match.group(3):
                fields["src_ip"] = asa_match.group(3)
            if asa_match.group(4):
                fields["src_port"] = int(asa_match.group(4))
            if asa_match.group(5):
                fields["dst_ip"] = asa_match.group(5)
            if asa_match.group(6):
                fields["dst_port"] = int(asa_match.group(6))
        else:
            # Fallback generic IP extraction
            ip_match = self._IP_PORT_PATTERN.search(msg_body)
            if ip_match:
                if ip_match.group(1):
                    fields["src_ip"] = ip_match.group(1)
                if ip_match.group(2):
                    fields["src_port"] = int(ip_match.group(2))
                if ip_match.group(3):
                    fields["dst_ip"] = ip_match.group(3)
                if ip_match.group(4):
                    fields["dst_port"] = int(ip_match.group(4))
            else:
                deductions.append("network endpoints not found in syslog body")

        # Protocol inference if missing
        if "protocol" not in fields:
            if " TCP " in upper_body or "TCP" in upper_body:
                fields["protocol"] = "TCP"
            elif " UDP " in upper_body or "UDP" in upper_body:
                fields["protocol"] = "UDP"
            elif " ICMP " in upper_body or "ICMP" in upper_body:
                fields["protocol"] = "ICMP"

        fields["message"] = msg_body

        return {
            "success": True,
            "fields": fields,
            "error": None,
            "timestamp": parsed_time,
            "confidence_deductions": deductions,
        }
