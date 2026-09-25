"""
services/log_forwarder_service.py
---------------------------------
Simulates log forwarding of canonical OCSF-aligned events to external SIEMs
or downstream systems (e.g. via Syslog/JSON to a file/socket).
"""

import json
import logging
import os
from pathlib import Path
from app.models.normalized_event import NormalizedEvent

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "outputs"
SIEM_STREAM_FILE = OUTPUT_DIR / "siem_stream.log"

class LogForwarderService:
    """Service to forward normalized events to external sinks."""

    @staticmethod
    def forward_event(normalized: NormalizedEvent) -> bool:
        """
        Forward the event to the external sink.
        For demonstration, we append it as a JSON line to outputs/siem_stream.log.
        """
        try:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            
            payload = {
                "event_id": normalized.normalized_event_id,
                "original_event_id": normalized.original_event_id,
                "class_name": normalized.class_name,
                "activity_name": normalized.activity_name,
                "action": normalized.action,
                "src_ip": normalized.src_ip,
                "dst_ip": normalized.dst_ip,
                "user_name": normalized.user_name,
                "process_name": normalized.process_name,
                "unmapped_data": normalized.unmapped_data,
                "normalization_confidence": normalized.normalization_confidence,
                "timestamp": normalized.event_time.isoformat() if normalized.event_time else None
            }
            
            with open(SIEM_STREAM_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
            
            logger.info(f"Forwarded event {normalized.normalized_event_id} to SIEM stream.")
            return True
        except Exception as e:
            logger.error(f"Failed to forward event to SIEM: {e}")
            return False
