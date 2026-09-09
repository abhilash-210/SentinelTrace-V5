# Sprint 3A Implementation Report — Semantic Policy Registry & Backend Management

**Project Name:** SentinelTrace  
**Architecture Version:** V5  
**Sprint Status:** PASS  
**Execution Date:** 2026-09-06  
**Document Version:** 1.0.0  

---

## 1. Executive Summary

Sprint 3A implements the **Semantic Policy Registry Database and Backend Management Layer** for SentinelTrace V5. SentinelTrace strictly decouples **structural parsing** (Sprint 2) from **semantic interpretation** (Sprint 3A). 

In traditional SIEM/log systems, raw field values like `action = "PERMIT"` are often globally assumed to mean `ALLOWED`. SentinelTrace rejects global unscoped mappings: all semantic equivalence interpretations are strictly scoped to vendor policies and source profiles. The identical raw token `PERMIT` resolves to `ALLOWED (COMPATIBLE)` under a Cisco ASA policy, but resolves to `MONITORED (AMBIGUOUS)` under a Demo Vendor observation policy.

Additionally, Sprint 3A introduces the **Protected Semantic Fields** catalog, safeguarding critical security-sensitive fields (`action.result`, `severity`, `authentication.outcome`) under elevated governance rules.

---

## 2. Architectural Architecture Added

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SENTINEL-TRACE PIPELINE V5                           │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │  Sprint 1: Evidence Vault     │
                   │  (Immutable Raw Ingestion)    │
                   └──────────────┬────────────────┘
                                  │
                                  ▼
                   ┌───────────────────────────────┐
                   │  Sprint 2: Structural Parser  │
                   │  (Syslog / JSON / CSV Extr.)  │
                   └──────────────┬────────────────┘
                                  │
                                  ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ SPRINT 3A: SEMANTIC POLICY REGISTRY & ISOLATION                        │
 │                                                                        │
 │   ┌───────────────────────────┐    ┌──────────────────────────────┐   │
 │   │  spol_cisco_asa_v1        │    │  spol_demo_vendor_v1         │   │
 │   │  PERMIT -> ALLOWED        │    │  PERMIT -> MONITORED         │   │
 │   │  (COMPATIBLE / LOW)       │    │  (AMBIGUOUS / MEDIUM)        │   │
 │   └─────────────┬─────────────┘    └──────────────┬───────────────┘   │
 │                 │                                 │                   │
 │                 ▼                                 ▼                   │
 │   ┌───────────────────────────────────────────────────────────────┐   │
 │   │             PROTECTED SEMANTIC FIELDS CATALOG                 │   │
 │   │   • action.result (CRITICAL)                                  │   │
 │   │   • severity (HIGH)                                           │   │
 │   │   • authentication.outcome (CRITICAL)                         │   │
 │   └───────────────────────────────────────────────────────────────┘   │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Database Schema

All tables reside within the dedicated PostgreSQL `sentinel` schema with foreign keys, indexes, and cascades.

### 3.1 `sentinel.semantic_policies`
| Column | Type | Constraints / Defaults | Description |
|---|---|---|---|
| `id` | `INTEGER` | Primary Key, Auto-increment | Surrogate database key |
| `policy_id` | `VARCHAR(64)` | Unique Index, Not Null | Human-readable ID (e.g. `spol_cisco_asa_v1`) |
| `policy_name` | `VARCHAR(255)` | Not Null | Policy title |
| `vendor_name` | `VARCHAR(255)` | Index, Not Null | Originating vendor / family |
| `source_profile_id` | `VARCHAR(64)` | Index, Not Null | Link to structural Source Profile |
| `version` | `INTEGER` | Default `1`, Not Null | Version number |
| `status` | `VARCHAR(32)` | Index, Default `DRAFT`, Not Null | State: `DRAFT`, `ACTIVE`, `SUPERSEDED`, `RETIRED` |
| `description` | `TEXT` | Nullable | Policy documentation and rationale |
| `supersedes_policy_id`| `VARCHAR(64)` | Nullable | Identifier of previous policy version |
| `created_at` | `TIMESTAMPTZ` | Default `CURRENT_TIMESTAMP`, Not Null | UTC creation timestamp |
| `updated_at` | `TIMESTAMPTZ` | Default `CURRENT_TIMESTAMP`, Not Null | UTC last update timestamp |

### 3.2 `sentinel.semantic_policy_rules`
| Column | Type | Constraints / Defaults | Description |
|---|---|---|---|
| `id` | `INTEGER` | Primary Key, Auto-increment | Surrogate database key |
| `rule_id` | `VARCHAR(64)` | Unique Index, Not Null | Rule identifier (e.g. `srule_cisco_01`) |
| `policy_id` | `VARCHAR(64)` | Foreign Key (`sentinel.semantic_policies.policy_id`), CASCADE | Scoping parent policy ID |
| `source_field` | `VARCHAR(100)`| Index, Not Null | Raw source field name (e.g. `action`) |
| `source_value` | `VARCHAR(255)`| Not Null | Raw vendor value (e.g. `PERMIT`) |
| `canonical_field` | `VARCHAR(100)`| Index, Not Null | Canonical target (e.g. `action.result`) |
| `canonical_value` | `VARCHAR(255)`| Not Null | Canonical value (e.g. `ALLOWED`, `MONITORED`) |
| `equivalence_classification` | `VARCHAR(32)` | Default `EQUIVALENT`, Not Null | `EQUIVALENT`, `COMPATIBLE`, `AMBIGUOUS`, `INCOMPATIBLE` |
| `risk_level` | `VARCHAR(32)` | Default `LOW`, Not Null | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `description` | `TEXT` | Nullable | Rule reasoning and edge-case notes |
| `created_at` | `TIMESTAMPTZ` | Default `CURRENT_TIMESTAMP`, Not Null | UTC creation timestamp |

### 3.3 `sentinel.protected_semantic_fields`
| Column | Type | Constraints / Defaults | Description |
|---|---|---|---|
| `id` | `INTEGER` | Primary Key, Auto-increment | Surrogate database key |
| `field_name` | `VARCHAR(100)`| Unique Index, Not Null | Canonical field path (e.g. `action.result`) |
| `criticality` | `VARCHAR(32)` | Default `HIGH`, Not Null | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `description` | `TEXT` | Not Null | Security significance documentation |
| `is_protected` | `BOOLEAN` | Default `true`, Not Null | Strict modification restriction flag |
| `created_at` | `TIMESTAMPTZ` | Default `CURRENT_TIMESTAMP`, Not Null | UTC creation timestamp |

---

## 4. Semantic Isolation & Vendor-Scoped Mappings

### 4.1 Rejection of Global Equivalence
In multi-vendor SIEM environments, assuming a global mapping like `PERMIT = ALLOWED` creates massive false negatives during threat detection. A vendor appliance running in monitor/tap mode might emit `action=PERMIT` to indicate passive capture rather than explicit enforcement.

SentinelTrace guarantees that **every rule must belong to a policy**, and **every policy is bound to a vendor/source profile**.

### 4.2 Seed Demonstration Policies
1. **Cisco ASA (`spol_cisco_asa_v1`)**:
   - `ALLOW` $\rightarrow$ `action.result = ALLOWED` (`EQUIVALENT`, `LOW`)
   - `DENY` $\rightarrow$ `action.result = DENIED` (`EQUIVALENT`, `LOW`)
   - `PERMIT` $\rightarrow$ `action.result = ALLOWED` (`COMPATIBLE`, `LOW`)
2. **Demo Vendor (`spol_demo_vendor_v1`)**:
   - `PERMIT` $\rightarrow$ `action.result = MONITORED` (`AMBIGUOUS`, `MEDIUM`)
   - `BLOCK` $\rightarrow$ `action.result = DENIED` (`EQUIVALENT`, `LOW`)
   - `PASS` $\rightarrow$ `action.result = ALLOWED` (`COMPATIBLE`, `LOW`)

---

## 5. Backend REST API Endpoints

| Method | Endpoint | Description | Lifecycle / Rules |
|---|---|---|---|
| `GET` | `/api/v1/semantic-policies` | List all registered semantic policies with metadata and rule counts | Returns all policies |
| `GET` | `/api/v1/semantic-policies/{policy_id}` | Detailed inspection of a specific policy including all scoped rules | 404 if not found |
| `GET` | `/api/v1/protected-fields` | List all security-sensitive canonical fields and their criticality | Sorted by criticality |
| `POST`| `/api/v1/semantic-policies` | Register a new vendor-scoped semantic policy | **Enforces `DRAFT` status** |

---

## 6. Verification and Test Results

### 6.1 Automated Test Execution Summary
- **Sprint 1 Tests (`test_sprint1_ingestion.py`)**: 8 / 8 PASSED
- **Sprint 2 Tests (`test_sprint2_normalization.py`)**: 10 / 10 PASSED
- **Sprint 3A Tests (`test_sprint3_semantic_registry.py`)**: 10 / 10 PASSED
- **Total Test Suite**: **28 / 28 PASSED (100%) in 0.652s**

### 6.2 Key Assertions Verified
1. ✅ Seed policies (`spol_cisco_asa_v1`, `spol_demo_vendor_v1`) exist and are `ACTIVE`.
2. ✅ Protected fields (`action.result` [CRITICAL], `severity` [HIGH], `authentication.outcome` [CRITICAL]) exist.
3. ✅ Raw token `PERMIT` produces distinct canonical outcomes (`ALLOWED` vs `MONITORED`) depending on policy.
4. ✅ Unscoped global queries are rejected (`/api/v1/semantic-policies/spol_global` returns 404).
5. ✅ Policy rules strictly enforce foreign key cascades upon deletion.
6. ✅ Newly registered policies are automatically forced to `DRAFT` status.
7. ✅ All regression tests from Sprint 1 and Sprint 2 continue to pass without errors.

---

## 7. Known Limitations

- **STIG Compliance & Dual-Control Approvals**: Rule promotion from `DRAFT` to `ACTIVE` currently requires administrative intervention; dual-control approval workflows are scheduled for Sprint 3B.
- **Dynamic Policy Application during Normalization**: Ingestion/normalization uses deterministic source profiling; full semantic policy rule application and drift detection engine will be coupled in Sprint 3B.
- **Frontend Management UI**: React UI components for visualizing policies and protected fields are scheduled for Sprint 3C.
