"""
demo_tamper_evidence.py
-----------------------
DEVELOPMENT / DEMO ONLY SCRIPT.

Simulates unauthorized direct database modification of a preserved raw event
WITHOUT updating its cryptographic SHA-256 fingerprint.

This demonstrates how SentinelTrace's live SHA-256 recalculation detects
data tampering and flags MISMATCH / TAMPER_DETECTED.

WARNING: Never expose this script or its logic as an API endpoint.
"""

import argparse
import os
import sys

# Ensure backend package can be imported
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy import select, text
from app.config import settings
from app.database import SessionLocal
from app.models.event import IngestedEvent
from app.services.event_service import compute_sha256


def simulate_tampering(event_id: str = None, replacement_text: str = None):
    print("=" * 70)
    print(" [DEVELOPMENT DEMO ONLY] SentinelTrace Evidence Tampering Simulator")
    print("=" * 70)
    print("⚠️  WARNING: Simulating out-of-band direct database modification...")
    print("⚠️  The raw_content will be modified WITHOUT updating raw_content_hash.")
    print("-" * 70)

    db = SessionLocal()
    try:
        if event_id:
            event = db.execute(
                select(IngestedEvent).where(IngestedEvent.event_id == event_id)
            ).scalar_one_or_none()
        else:
            # Pick the most recent event
            event = db.execute(
                select(IngestedEvent).order_by(IngestedEvent.ingested_at.desc()).limit(1)
            ).scalar_one_or_none()

        if not event:
            print("❌ No event found in database to tamper with.")
            return

        print(f"Target Event ID   : {event.event_id}")
        print(f"Source System     : {event.source_name} ({event.source_type})")
        print(f"Original SHA-256  : {event.raw_content_hash}")
        print(f"Original Content  : {event.raw_content[:80]}...")
        print("-" * 70)

        original_content = event.raw_content
        if replacement_text:
            tampered_content = replacement_text
        elif "ALLOW" in original_content:
            tampered_content = original_content.replace("ALLOW", "DENY")
        elif "DENY" in original_content:
            tampered_content = original_content.replace("DENY", "ALLOW")
        elif "SUCCESS" in original_content:
            tampered_content = original_content.replace("SUCCESS", "FAILURE")
        else:
            tampered_content = original_content + "\n[TAMPERED_PAYLOAD_INJECTED_OUT_OF_BAND]"

        # Directly update raw_content in PostgreSQL WITHOUT updating raw_content_hash
        event.raw_content = tampered_content
        event.content_size = len(tampered_content.encode("utf-8"))
        db.commit()

        new_live_hash = compute_sha256(tampered_content)

        print("✅ Tampering applied successfully to database:")
        print(f"Tampered Content  : {tampered_content[:80]}...")
        print(f"Stored Hash (old) : {event.raw_content_hash}")
        print(f"Calculated Hash   : {new_live_hash}")
        print("-" * 70)
        print("Expected verification result: ⚠ MISMATCH / TAMPER DETECTED")
        print(f"Run GET /api/v1/events/{event.event_id}/verify to test.")
        print("=" * 70)

    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Demo tamper evidence simulator (DEV ONLY)")
    parser.add_argument("--event-id", type=str, help="Specific event ID to tamper with", default=None)
    parser.add_argument("--text", type=str, help="Custom tampered replacement text", default=None)
    args = parser.parse_args()
    simulate_tampering(args.event_id, args.text)
