import json
import time
import urllib.request
import urllib.error

API_URL = "http://localhost:8000/api/v1"

def request_json(url, data=None, headers=None, method="GET"):
    if headers is None:
        headers = {}
    
    if data is not None:
        if isinstance(data, dict):
            data_bytes = json.dumps(data).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        elif isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
    else:
        data_bytes = None
        
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.read().decode()}")
        raise

def authenticate():
    print("1. Authenticating as admin_demo via API...")
    payload = {"username": "admin_demo", "password": "SentinelDemo!2026"}
    res = request_json(f"{API_URL}/auth/login", data=payload, method="POST")
    return res["access_token"]

def main():
    token = authenticate()
    headers = {"Authorization": f"Bearer {token}"}
    
    print("\n--- PHASE 1: INGESTION & PRESERVE (Invalid Event) ---")
    payload = {
        "source_name": "Auth-Gateway-Node",
        "source_type": "authentication",
        "file_format": "json",
        "raw_content": '{"timestamp": "2026-09-06T12:05:30.450Z", "service": "auth-gateway", "event_type": "AUTHENTICATION_FAILURE", "client_ip": "198.51.100.77"',
        "metadata": {"environment": "staging"}
    }
    print("Payload sent (missing closing bracket):", payload["raw_content"])
    ingest_data = request_json(f"{API_URL}/ingest", data=payload, headers=headers, method="POST")
    
    event_id = ingest_data["event_id"]
    original_hash = ingest_data["raw_content_hash"]
    print(f"Success! Preserved Event ID: {event_id}")
    print(f"SHA-256 Hash Generated: {original_hash}")
    
    print("\n--- PHASE 2: PARSE & NORMALIZE (Should Fail & Quarantine) ---")
    norm_res = request_json(f"{API_URL}/events/{event_id}/normalize", data={}, headers=headers, method="POST")
    print(f"Normalization Result Status: {norm_res.get('normalization_status')}")

    print("\n--- PHASE 3: QUARANTINE VERIFICATION ---")
    event_details = request_json(f"{API_URL}/events/{event_id}", headers=headers)
    status = event_details.get("processing_status")
    print(f"Event Status in DB: {status}")
    if status != "FAILED":
        print("Wait, event wasn't marked FAILED? Quarantined?")
    
    dlq_items = request_json(f"{API_URL}/quarantine?status=PENDING", headers=headers).get("items", [])
    quarantine_id = None
    for item in dlq_items:
        if item["original_event_id"] == event_id:
            quarantine_id = item["quarantine_id"]
            break
            
    print(f"Quarantine Record ID: {quarantine_id}")
    
    if not quarantine_id:
        print("ERROR: Event not found in quarantine!")
        return
        
    print("\n--- PHASE 4: REPLAY WITH FIX ---")
    fixed_payload = '{"timestamp": "2026-09-06T12:05:30.450Z", "service": "auth-gateway", "event_type": "AUTHENTICATION_FAILURE", "client_ip": "198.51.100.77"}'
    print(f"Submitting fixed payload: {fixed_payload}")
    replay_data = {
        "quarantine_id": quarantine_id,
        "corrected_raw_content": fixed_payload,
        "notes": "Fixed missing closing brace"
    }
    replay_res = request_json(f"{API_URL}/quarantine/replay", data=replay_data, headers=headers, method="POST")
    print(f"Replay successful. Result status: {replay_res['status']}")
    
    print("\n--- PHASE 5: OCSF NORMALIZATION CHECK (Post-Replay) ---")
    event_details = request_json(f"{API_URL}/events/{event_id}", headers=headers)
    print(f"Updated Event Status: {event_details.get('processing_status')}")
    
    print("\n--- PHASE 6: CRYPTOGRAPHIC INTEGRITY AUDIT ---")
    print("Testing if the original hash remains valid despite the replay fixing the data...")
    verify_data = request_json(f"{API_URL}/events/{event_id}/verify", headers=headers)
    print(f"Stored Hash: {verify_data['stored_hash']}")
    print(f"Calculated Hash: {verify_data['calculated_hash']}")
    print(f"Integrity Status: {verify_data['integrity_status']}")
    
    if verify_data["integrity_status"] == "VERIFIED":
        print("\n✅ END-TO-END WORKFLOW VERIFIED SUCCESSFULLY! Original evidence preserved unaltered while corrected data was replayed.")
    else:
        print("\n❌ INTEGRITY FAILED. Original evidence was tampered with.")

if __name__ == "__main__":
    main()
