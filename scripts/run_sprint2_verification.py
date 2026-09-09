"""
run_sprint2_verification.py
---------------------------
Sprint 2 Verification & Evidence Capture Runner.
Ingests heterogeneous sample logs (Syslog, JSON, CSV), normalizes them, verifies traceability,
validates idempotency, runs automated tests, and saves UTF-8 evidence logs.
"""

import json
import os
import subprocess
import httpx

EVIDENCE_LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "evidence", "sprint-02", "logs")
os.makedirs(EVIDENCE_LOGS_DIR, exist_ok=True)

print("=== Running Sprint 2 Verification & Evidence Capture ===")

# 1. Automated Tests Log
print("\n[1/5] Running automated tests (Sprint 1 + Sprint 2)...")
cmd = ["docker", "exec", "sentinel-trace-backend", "python", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"]
res_test = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
print(res_test.stdout + res_test.stderr)
with open(os.path.join(EVIDENCE_LOGS_DIR, "automated-tests.txt"), "w", encoding="utf-8") as f:
    f.write("=== SENTINEL-TRACE V5 — SPRINT 2 AUTOMATED TEST SUITE ===\n\n")
    f.write(res_test.stdout + "\n" + res_test.stderr)

# 2. Docker Services Status
print("\n[2/5] Capturing Docker services status...")
cmd_ps = ["docker", "compose", "ps"]
res_ps = subprocess.run(cmd_ps, capture_output=True, text=True, encoding="utf-8")
print(res_ps.stdout)
with open(os.path.join(EVIDENCE_LOGS_DIR, "docker-services-status.txt"), "w", encoding="utf-8") as f:
    f.write("=== SENTINEL-TRACE V5 — DOCKER SERVICES STATUS ===\n\n")
    f.write(res_ps.stdout + "\n" + res_ps.stderr)

# 3. Normalization API Test for 3 Formats
print("\n[3/5] Ingesting and Normalizing Sample Formats (Syslog, JSON, CSV)...")

# Sample 1: Firewall Syslog
sample_dir = os.path.join(os.path.dirname(__file__), "..", "sample-data")
with open(os.path.join(sample_dir, "firewall_sample.log"), "r", encoding="utf-8") as f:
    fw_content = f.read()

r_ingest_fw = httpx.post("http://localhost:8000/api/v1/ingest", json={
    "source_name": "perimeter-fw-01",
    "source_type": "firewall",
    "file_format": "text",
    "raw_content": fw_content,
    "metadata": {"zone": "perimeter"}
})
fw_event_id = r_ingest_fw.json()["event_id"]
r_norm_fw = httpx.post(f"http://localhost:8000/api/v1/events/{fw_event_id}/normalize")
fw_norm_json = r_norm_fw.json()

# Sample 2: Auth JSON
with open(os.path.join(sample_dir, "application_event.json"), "r", encoding="utf-8") as f:
    auth_content = f.read()

r_ingest_auth = httpx.post("http://localhost:8000/api/v1/ingest", json={
    "source_name": "auth-gateway-01",
    "source_type": "authentication",
    "file_format": "json",
    "raw_content": auth_content,
    "metadata": {"zone": "iam"}
})
auth_event_id = r_ingest_auth.json()["event_id"]
r_norm_auth = httpx.post(f"http://localhost:8000/api/v1/events/{auth_event_id}/normalize")
auth_norm_json = r_norm_auth.json()

# Sample 3: System CSV
with open(os.path.join(sample_dir, "system_events.csv"), "r", encoding="utf-8") as f:
    sys_content = f.read()

r_ingest_sys = httpx.post("http://localhost:8000/api/v1/ingest", json={
    "source_name": "srv-app-prod-01",
    "source_type": "system",
    "file_format": "csv",
    "raw_content": sys_content,
    "metadata": {"zone": "app-cluster"}
})
sys_event_id = r_ingest_sys.json()["event_id"]
r_norm_sys = httpx.post(f"http://localhost:8000/api/v1/events/{sys_event_id}/normalize")
sys_norm_json = r_norm_sys.json()

with open(os.path.join(EVIDENCE_LOGS_DIR, "normalization-api-test.txt"), "w", encoding="utf-8") as f:
    f.write("=== SENTINEL-TRACE V5 — NORMALIZATION API TEST (3 FORMATS) ===\n\n")
    f.write("--- FORMAT 1: Plain Text / Syslog Firewall ---\n")
    f.write(f"Raw Event ID: {fw_event_id}\n")
    f.write(f"Normalized Output:\n{json.dumps(fw_norm_json, indent=2)}\n\n")
    f.write("--- FORMAT 2: Structured JSON Application Auth ---\n")
    f.write(f"Raw Event ID: {auth_event_id}\n")
    f.write(f"Normalized Output:\n{json.dumps(auth_norm_json, indent=2)}\n\n")
    f.write("--- FORMAT 3: Tabular CSV System Audit ---\n")
    f.write(f"Raw Event ID: {sys_event_id}\n")
    f.write(f"Normalized Output:\n{json.dumps(sys_norm_json, indent=2)}\n")

print(f"  ✓ Normalized Syslog -> {fw_norm_json['class_name']} ({fw_norm_json['normalized_event_id']})")
print(f"  ✓ Normalized JSON   -> {auth_norm_json['class_name']} ({auth_norm_json['normalized_event_id']})")
print(f"  ✓ Normalized CSV    -> {sys_norm_json['class_name']} ({sys_norm_json['normalized_event_id']})")

# 4. Idempotency Test
print("\n[4/5] Testing Normalization Idempotency...")
r_norm_repeat = httpx.post(f"http://localhost:8000/api/v1/events/{fw_event_id}/normalize")
repeat_json = r_norm_repeat.json()
is_idempotent = (
    fw_norm_json["normalized_event_id"] == repeat_json["normalized_event_id"]
    and fw_norm_json["id"] == repeat_json["id"]
)
print(f"  Idempotency Check: {is_idempotent} (Returned existing ID {repeat_json['normalized_event_id']})")

with open(os.path.join(EVIDENCE_LOGS_DIR, "idempotency-test.txt"), "w", encoding="utf-8") as f:
    f.write("=== SENTINEL-TRACE V5 — NORMALIZATION IDEMPOTENCY TEST ===\n\n")
    f.write(f"Target Event: {fw_event_id}\n")
    f.write(f"First Call Normalized ID:  {fw_norm_json['normalized_event_id']}\n")
    f.write(f"Second Call Normalized ID: {repeat_json['normalized_event_id']}\n")
    f.write(f"Database Record PK Match:  {fw_norm_json['id'] == repeat_json['id']}\n")
    f.write(f"Idempotency Confirmed:     {is_idempotent}\n")

# 5. Traceability Link Test
print("\n[5/5] Testing Evidence-to-Canonical Traceability...")
r_trace = httpx.get(f"http://localhost:8000/api/v1/events/{fw_event_id}/normalization")
trace_json = r_trace.json()
print("Traceability API Response HTTP", r_trace.status_code)
print(json.dumps(trace_json, indent=2))

with open(os.path.join(EVIDENCE_LOGS_DIR, "traceability-test.txt"), "w", encoding="utf-8") as f:
    f.write("=== SENTINEL-TRACE V5 — BIDIRECTIONAL TRACEABILITY TEST ===\n\n")
    f.write(f"Endpoint: GET http://localhost:8000/api/v1/events/{fw_event_id}/normalization\n")
    f.write(f"HTTP Status: {r_trace.status_code}\n")
    f.write(f"Traceability Mapping:\n{json.dumps(trace_json, indent=2)}\n")

print("\n✅ All Sprint 2 verification logs captured successfully!")
