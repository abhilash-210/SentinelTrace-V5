"""
run_sprint1_verification.py
---------------------------
Verification & evidence logging script for Sprint 1.
Executes real tests, captures output, and saves UTF-8 log files.
"""

import json
import os
import subprocess
import httpx

EVIDENCE_LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "evidence", "sprint-01", "logs")
os.makedirs(EVIDENCE_LOGS_DIR, exist_ok=True)

print("=== Running Sprint 1 Verification & Evidence Capture ===")

# 1. Automated Tests Log
print("\n[1/5] Running automated tests...")
cmd = ["docker", "exec", "sentinel-trace-backend", "python", "-m", "unittest", "tests/test_sprint1_ingestion.py", "-v"]
res_test = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
print(res_test.stdout + res_test.stderr)
with open(os.path.join(EVIDENCE_LOGS_DIR, "automated-tests.txt"), "w", encoding="utf-8") as f:
    f.write("=== SENTINEL-TRACE V5 — SPRINT 1 AUTOMATED TESTS ===\n\n")
    f.write(res_test.stdout + "\n" + res_test.stderr)

# 2. Docker Services Status
print("\n[2/5] Capturing Docker services status...")
cmd_ps = ["docker", "compose", "ps"]
res_ps = subprocess.run(cmd_ps, capture_output=True, text=True, encoding="utf-8")
print(res_ps.stdout)
with open(os.path.join(EVIDENCE_LOGS_DIR, "docker-services-status.txt"), "w", encoding="utf-8") as f:
    f.write("=== SENTINEL-TRACE V5 — DOCKER SERVICES STATUS ===\n\n")
    f.write(res_ps.stdout + "\n" + res_ps.stderr)

# 3. API Ingestion Test
print("\n[3/5] Testing API Ingestion...")
payload = {
    "source_name": "Cisco ASA Firewall",
    "source_type": "firewall",
    "file_format": "text",
    "raw_content": "<13>Sep 06 12:34:56 firewall-01 %ASA-6-302013: Built inbound TCP connection 12345 for outside:185.10.20.5/443 to inside:10.0.0.15/51515 action=ALLOW",
    "metadata": {"environment": "demo", "location": "perimeter"}
}
r_ingest = httpx.post("http://localhost:8000/api/v1/ingest", json=payload)
ingest_json = r_ingest.json()
print("Ingestion Response HTTP", r_ingest.status_code)
print(json.dumps(ingest_json, indent=2))
event_id = ingest_json["event_id"]

with open(os.path.join(EVIDENCE_LOGS_DIR, "api-ingestion-test.txt"), "w", encoding="utf-8") as f:
    f.write("=== SENTINEL-TRACE V5 — API INGESTION TEST ===\n\n")
    f.write(f"Endpoint: POST http://localhost:8000/api/v1/ingest\n")
    f.write(f"Request Payload:\n{json.dumps(payload, indent=2)}\n\n")
    f.write(f"HTTP Status: {r_ingest.status_code}\n")
    f.write(f"Response Body:\n{json.dumps(ingest_json, indent=2)}\n")

# 4. Integrity Verification Test (Unmodified)
print("\n[4/5] Testing Integrity Verification (Unmodified)...")
r_verify = httpx.get(f"http://localhost:8000/api/v1/events/{event_id}/verify")
verify_json = r_verify.json()
print("Verification Response HTTP", r_verify.status_code)
print(json.dumps(verify_json, indent=2))

with open(os.path.join(EVIDENCE_LOGS_DIR, "integrity-verification-test.txt"), "w", encoding="utf-8") as f:
    f.write("=== SENTINEL-TRACE V5 — INTEGRITY VERIFICATION TEST ===\n\n")
    f.write(f"Endpoint: GET http://localhost:8000/api/v1/events/{event_id}/verify\n")
    f.write(f"HTTP Status: {r_verify.status_code}\n")
    f.write(f"Response Body:\n{json.dumps(verify_json, indent=2)}\n")

# 5. Tamper Detection Test
print("\n[5/5] Testing Tamper Detection...")
# Tamper with event in DB
subprocess.run([
    "docker", "exec", "sentinel-trace-backend", "python", "-c",
    f"""
from app.database import SessionLocal
from app.models.event import IngestedEvent
db = SessionLocal()
evt = db.query(IngestedEvent).filter(IngestedEvent.event_id == '{event_id}').first()
if evt:
    evt.raw_content = evt.raw_content.replace('action=ALLOW', 'action=DENY')
    db.commit()
db.close()
"""
], capture_output=True, text=True)

# Verify tampered event
r_tamper_verify = httpx.get(f"http://localhost:8000/api/v1/events/{event_id}/verify")
tamper_json = r_tamper_verify.json()
print("Tampered Verification Response HTTP", r_tamper_verify.status_code)
print(json.dumps(tamper_json, indent=2))

with open(os.path.join(EVIDENCE_LOGS_DIR, "tamper-detection-test.txt"), "w", encoding="utf-8") as f:
    f.write("=== SENTINEL-TRACE V5 — TAMPER DETECTION DEMONSTRATION ===\n\n")
    f.write(f"Action: Modified database raw_content from 'action=ALLOW' to 'action=DENY' without updating hash.\n")
    f.write(f"Endpoint: GET http://localhost:8000/api/v1/events/{event_id}/verify\n")
    f.write(f"HTTP Status: {r_tamper_verify.status_code}\n")
    f.write(f"Response Body:\n{json.dumps(tamper_json, indent=2)}\n")

print("\n✅ All Sprint 1 verification logs captured successfully!")
