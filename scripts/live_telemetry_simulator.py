#!/usr/bin/env python3
"""
scripts/live_telemetry_simulator.py
-----------------------------------
Standalone Live Multi-Source Telemetry Simulator for SentinelTrace V5.

Continuously sends realistic SYNTHETIC security events into the ingestion API.
These are simulated/generated logs designed to demonstrate the ULPF ingestion,
parsing, normalization, validation, and quarantine pipelines.
"""

import argparse
import json
import random
import time
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone

# Simulated sources configuration
SOURCES = [
    {"name": "FIREWALL-A", "type": "FIREWALL", "format": "syslog"},
    {"name": "ROUTER-B", "type": "ROUTER", "format": "cef"},
    {"name": "FIREWALL-C", "type": "FIREWALL", "format": "json"},
    {"name": "APP-D", "type": "APPLICATION", "format": "csv"},
    {"name": "AUTH-E", "type": "AUTHENTICATION", "format": "json"},
]

def generate_syslog(is_malformed: bool) -> str:
    now = datetime.now().strftime("%b %d %H:%M:%S")
    ips = ["192.168.1.50", "10.0.0.5", "172.16.0.10"]
    users = ["admin", "root", "guest", "service_account"]
    
    if is_malformed:
        return f"<{random.randint(1, 100)}{now} kernel: [  123.456] Something broke"
    
    action = random.choice(["Accepted", "Failed"])
    ip = random.choice(ips)
    user = random.choice(users)
    return f"<{random.randint(1, 191)}>{now} firewall-a sshd[1234]: {action} password for {user} from {ip} port {random.randint(1024, 65535)} ssh2"

def generate_cef(is_malformed: bool) -> str:
    if is_malformed:
        return "CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|cs1Label=MissingValue cs1="
    
    ips = ["192.168.1.50", "10.0.0.5", "172.16.0.10"]
    ip = random.choice(ips)
    action = random.choice(["blocked", "allowed"])
    return f"CEF:0|SentinelTrace|Router-B|1.0|100|Traffic {action}|5|src={ip} spt={random.randint(1000, 9999)} dst=8.8.8.8 dpt=443 act={action}"

def generate_json(is_malformed: bool, source_name: str) -> str:
    if is_malformed:
        return '{ "action": "SUCCESS", "src_ip": "1.1.1.1", "incomplete"'
        
    ips = ["10.10.10.10", "192.168.100.1"]
    users = ["jdoe", "asmith", "bwayne"]
    
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": random.choice(["SUCCESS", "FAILURE"]),
        "src_ip": random.choice(ips),
        "user_name": random.choice(users),
        "src_port": random.randint(10000, 60000),
        "protocol": "TCP",
        "vendor_field_x": f"x_{random.randint(100, 999)}" # Unmapped data
    }
    
    if "FIREWALL" in source_name:
        data["dst_ip"] = "8.8.8.8"
        data["dst_port"] = 443
        
    return json.dumps(data)

def generate_csv(is_malformed: bool) -> str:
    if is_malformed:
        return "2023-10-10T10:10:10Z,missing_fields"
        
    now = datetime.now(timezone.utc).isoformat()
    action = random.choice(["SUCCESS", "FAILURE"])
    user = random.choice(["app_user", "db_admin"])
    ip = f"10.0.0.{random.randint(1, 255)}"
    # Time, SrcIP, User, Action, Protocol, Port
    return f"{now},{ip},{user},{action},HTTPS,{random.randint(1024, 65535)}"

def generate_event(pct_malformed: int) -> dict:
    source = random.choice(SOURCES)
    is_malformed = random.randint(1, 100) <= pct_malformed
    
    if source["format"] == "syslog":
        raw = generate_syslog(is_malformed)
    elif source["format"] == "cef":
        raw = generate_cef(is_malformed)
    elif source["format"] == "json":
        raw = generate_json(is_malformed, source["name"])
    elif source["format"] == "csv":
        raw = generate_csv(is_malformed)
    else:
        raw = "unknown format"
        
    return {
        "source_name": source["name"] if not is_malformed else "UNKNOWN-X",
        "source_type": source["type"],
        "file_format": source["format"],
        "raw_content": raw,
        "metadata": {"simulated": True, "generator": "live_telemetry_simulator.py"},
        "is_malformed": is_malformed
    }

def main():
    parser = argparse.ArgumentParser(description="Live Telemetry Simulator for SentinelTrace")
    parser.add_argument("--url", default="http://localhost:8000/api/v1/ingest", help="Ingestion API URL")
    parser.add_argument("--eps", type=float, default=1.0, help="Events per second")
    parser.add_argument("--malformed-pct", type=int, default=10, help="Percentage of malformed events (0-100)")
    parser.add_argument("--duration", type=int, default=0, help="Run duration in seconds (0 for continuous)")
    parser.add_argument("--token", default="ADMIN", help="Authorization token (Bearer)")
    
    args = parser.parse_args()
    
    print(f"[*] Starting SentinelTrace Live Telemetry Simulator")
    print(f"[*] Target URL: {args.url}")
    print(f"[*] Speed: {args.eps} EPS")
    print(f"[*] Malformed Rate: {args.malformed_pct}%")
    print(f"[*] Duration: {'Continuous' if args.duration == 0 else f'{args.duration}s'}")
    print("-" * 50)
    
    start_time = time.time()
    events_sent = 0
    headers = {
        "Authorization": f"Bearer {args.token}",
        "Content-Type": "application/json"
    }
    
    interval = 1.0 / args.eps if args.eps > 0 else 0
    
    try:
        while True:
            current_time = time.time()
            if args.duration > 0 and (current_time - start_time) >= args.duration:
                break
                
            event_data = generate_event(args.malformed_pct)
            is_malformed = event_data.pop("is_malformed")
            
            try:
                # 1. Ingest
                req = urllib.request.Request(
                    args.url,
                    data=json.dumps(event_data).encode("utf-8"),
                    headers=headers,
                    method="POST"
                )
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                try:
                    with urllib.request.urlopen(req, timeout=2, context=ctx) as res:
                        status_code = res.status
                        body = res.read().decode("utf-8")
                        res_json = json.loads(body)
                except urllib.error.HTTPError as e:
                    status_code = e.code
                    res_json = {}
                
                timestamp_str = datetime.now().strftime("%H:%M:%S")
                
                if status_code == 201:
                    evt_id = res_json.get("event_id")
                    
                    # 2. Automatically trigger normalizer for the simulator pipeline effect
                    norm_url = args.url.replace("/ingest", f"/events/{evt_id}/normalize")
                    norm_req = urllib.request.Request(
                        norm_url,
                        headers=headers,
                        method="POST"
                    )
                    
                    try:
                        with urllib.request.urlopen(norm_req, timeout=2, context=ctx) as norm_res:
                            norm_status_code = norm_res.status
                            norm_body = norm_res.read().decode("utf-8")
                            norm_json = json.loads(norm_body)
                    except urllib.error.HTTPError as e:
                        norm_status_code = e.code
                        norm_json = {}
                    
                    if norm_status_code == 200:
                        norm_status = norm_json.get("normalization_status")
                        if norm_status in ("FAILED", "INVALID"):
                            status_label = "QUARANTINED"
                        else:
                            status_label = "NORMALIZED"
                    else:
                        status_label = "NORM_ERR"
                        
                    print(f"[{timestamp_str}] {event_data['source_name']:<12} | {event_data['file_format'].upper():<6} | {status_label}")
                else:
                    print(f"[{timestamp_str}] {event_data['source_name']:<12} | {event_data['file_format'].upper():<6} | API_ERR {status_code}")
                    
            except (urllib.error.URLError, TimeoutError) as e:
                timestamp_str = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp_str}] CONNECTION ERROR: {e}")
                
            events_sent += 1
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n[*] Simulator stopped by user.")
        
    print("-" * 50)
    print(f"[*] Total events generated: {events_sent}")
    print(f"[*] Elapsed time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
