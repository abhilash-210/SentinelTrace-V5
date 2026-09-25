# Sample Source Profiles for SentinelTrace V5
# Submit these via POST /api/v1/source-profiles to register new sources.

---

## 1. Cisco ASA Firewall (Syslog)

```json
{
  "source_name": "perimeter-fw-01",
  "source_type": "firewall",
  "file_format": "text",
  "vendor": "Cisco",
  "product": "ASA",
  "description": "Perimeter firewall — north zone",
  "field_mappings": {
    "action": "action",
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "protocol": "protocol"
  },
  "tags": ["perimeter", "production", "north-zone"]
}
```

---

## 2. Authentication Gateway (JSON)

```json
{
  "source_name": "auth-gateway-node",
  "source_type": "authentication",
  "file_format": "json",
  "vendor": "Internal",
  "product": "AuthGateway",
  "description": "Internal MFA authentication service",
  "field_mappings": {
    "user_name": "username",
    "action": "event_type",
    "src_ip": "client_ip"
  },
  "tags": ["authentication", "mfa", "staging"]
}
```

---

## 3. Linux Server Process Audit (CSV)

```json
{
  "source_name": "srv-app-prod-01",
  "source_type": "system",
  "file_format": "csv",
  "vendor": "Linux",
  "product": "auditd",
  "description": "Application server process audit log",
  "field_mappings": {
    "hostname": "hostname",
    "process_name": "process_name",
    "user_name": "user",
    "action": "action"
  },
  "tags": ["server", "audit", "production"]
}
```
