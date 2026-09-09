# Sprint 4A Completion Report — Identity & Role-Based Access Control (RBAC)

**Project**: SENTINEL-TRACE (SIH 2026 Prototype)  
**Architecture Version**: V5  
**Sprint**: Sprint 4A (Identity & RBAC)  
**Status**: **COMPLETE & FROZEN (PASS)**  
**Verification Baseline**: 67/67 Automated Unit & Integration Tests Passing (0 Failed, 0 Regressions)

---

## 1. Executive Summary

Sprint 4A establishes **authenticated identity and fine-grained Role-Based Access Control (RBAC)** across SentinelTrace. Prior to Sprint 4A, semantic policies and log pipelines operated without individual identity context. Sprint 4A introduces the foundational security principle of **Attribution and Access Guarding**:

$$\text{User} \longrightarrow \text{Authentication} \longrightarrow \text{Identity Context} \longrightarrow \text{Role} \longrightarrow \text{Permission Evaluation} \longrightarrow \text{Governance Action}$$

Every sensitive action in the system is now bound to:
1. **WHO** performed it (`current_user.user_id`, `current_user.username`)
2. **WHAT** role they have (`current_user.role`)
3. **WHEN** it happened (`created_at`, `timestamp`)

---

## 2. Architecture & Identity Model

### 2.1 Database Schema (`sentinel.users`)

Managed via Alembic migration (`d4e5f6a7b8c9_create_identity_and_rbac_tables.py`):

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `INTEGER` | Primary Key, Autoincrement | Internal sequence ID |
| `user_id` | `VARCHAR(64)` | Unique, Indexed, Non-null | Unique identifier (`usr_<uuid>`) |
| `username` | `VARCHAR(64)` | Unique, Indexed, Non-null | Unique login handle |
| `email` | `VARCHAR(128)` | Unique, Indexed, Non-null | Contact email address |
| `full_name` | `VARCHAR(128)` | Non-null | Human-readable user name |
| `password_hash`| `VARCHAR(255)` | Non-null | Bcrypt hashed credential (never plaintext) |
| `role` | `VARCHAR(32)` | Non-null, Indexed | Enum: `ADMIN`, `POLICY_AUTHOR`, `POLICY_REVIEWER`, `SECURITY_ANALYST`, `AUDITOR`, `VIEWER` |
| `is_active` | `BOOLEAN` | Default `True` | Account lifecycle toggle |
| `created_at` | `TIMESTAMPTZ` | Default `now()` | Timestamp of registration |
| `updated_at` | `TIMESTAMPTZ` | On update `now()` | Timestamp of last modification |
| `last_login_at`| `TIMESTAMPTZ` | Nullable | Timestamp of last successful JWT issue |

---

## 3. RBAC Roles & Centralized Permission Matrix

SentinelTrace implements a centralized role-to-permission mapping service in `app/core/rbac.py` avoiding scattered inline checks.

### 3.1 Role Taxonomy

1. **`ADMIN`**: Full platform control, user registration, role provisioning, and unrestricted read/manage access.
2. **`POLICY_AUTHOR`**: Creates and modifies vendor-scoped semantic policies in `DRAFT` state; compares policy versions.
3. **`POLICY_REVIEWER`**: Inspects semantic policies, evaluates version differences, and monitors drift telemetry.
4. **`SECURITY_ANALYST`**: Ingests raw evidence, triggers OCSF normalization, executes semantic interpretation, and monitors alerts.
5. **`AUDITOR`**: Comprehensive read-only audit access to Evidence Vault, OCSF normalized logs, semantic policies, and complete end-to-end traceability chains.
6. **`VIEWER`**: Read-only telemetry and dashboard inspection.

### 3.2 Permission Matrix

| Permission | `ADMIN` | `SECURITY_ANALYST` | `POLICY_AUTHOR` | `POLICY_REVIEWER` | `AUDITOR` | `VIEWER` |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `USER_MANAGE` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `USER_READ` | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| `EVIDENCE_INGEST` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `EVIDENCE_READ` | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| `EVENT_NORMALIZE` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `NORMALIZED_EVENT_READ` | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| `SEMANTIC_POLICY_CREATE` | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| `SEMANTIC_POLICY_EDIT_DRAFT` | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| `SEMANTIC_POLICY_READ` | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `SEMANTIC_POLICY_COMPARE` | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| `SEMANTIC_INTERPRET` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `DRIFT_ALERT_READ` | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| `AUDIT_READ` | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |

---

## 4. Protected API Endpoints

All sensitive operations are guarded by FastAPI dependencies `get_current_user` and `require_permission(permission)`:

- `POST /api/v1/ingest` $\rightarrow$ Requires `EVIDENCE_INGEST` (Analyst/Admin)
- `GET /api/v1/events` $\rightarrow$ Requires `EVIDENCE_READ` (Analyst/Auditor/Admin)
- `GET /api/v1/events/{id}/verify` $\rightarrow$ Requires `EVIDENCE_READ` (Analyst/Auditor/Admin)
- `POST /api/v1/events/{id}/normalize` $\rightarrow$ Requires `EVENT_NORMALIZE` (Analyst/Admin)
- `GET /api/v1/normalized-events` $\rightarrow$ Requires `NORMALIZED_EVENT_READ`
- `POST /api/v1/semantic-policies` $\rightarrow$ Requires `SEMANTIC_POLICY_CREATE` (Author/Admin)
- `GET /api/v1/semantic-policies/compare` $\rightarrow$ Requires `SEMANTIC_POLICY_COMPARE`
- `POST /api/v1/normalized-events/{id}/interpret` $\rightarrow$ Requires `SEMANTIC_INTERPRET` (Analyst/Admin)
- `GET /api/v1/semantic-interpretations/{id}/trace` $\rightarrow$ Requires `AUDIT_READ` (Auditor/Admin)
- `GET /api/v1/users` $\rightarrow$ Requires `USER_READ` (Admin/Auditor)
- `POST /api/v1/users` $\rightarrow$ Requires `USER_MANAGE` (Admin)
- `PATCH /api/v1/users/{id}` $\rightarrow$ Requires `USER_MANAGE` (Admin)

---

## 5. Pre-Seeded Development Identities

| Username | Role | Full Name | Email |
|---|---|---|---|
| `admin_demo` | `ADMIN` | System Administrator | `admin@sentineltrace.io` |
| `analyst_demo` | `SECURITY_ANALYST` | Abhilash (Security Analyst) | `analyst@sentineltrace.io` |
| `author_demo` | `POLICY_AUTHOR` | Dr. Elena Vance (Policy Author) | `author@sentineltrace.io` |
| `reviewer_demo` | `POLICY_REVIEWER` | Marcus Holloway (Governance Reviewer) | `reviewer@sentineltrace.io` |
| `auditor_demo` | `AUDITOR` | Sarah Connor (Compliance Auditor) | `auditor@sentineltrace.io` |
| `viewer_demo` | `VIEWER` | Guest Security Observer | `viewer@sentineltrace.io` |

*(Note: Pre-seeded accounts are strictly configured for local hackathon and development validation).*

---

## 6. Frontend Security Experience

1. **Login Interface (`/login`)**: Dark cybersecurity theme with brand messaging, JWT credential submission, and 1-click collapsible development role quick-fill selector.
2. **Global Auth Context (`AuthContext.jsx`)**: Injects JWT Bearer tokens transparently across API transactions.
3. **Role-Aware Sidebar (`Sidebar.jsx`)**: Automatically filters navigation routes based on user role grants.
4. **Access Denied Modal (`AccessRestricted.jsx`)**: High-contrast HTTP 403 screen detailing user's current role and the exact missing permission.
5. **Identity Profile (`/profile`)**: Displays user identifier, account state, and active permission matrix.
6. **User Governance (`/users`)**: Admin-only user directory with status toggling and role assignment.

---

## 7. Verification Evidence & Test Summary

- **Total Automated Tests**: 67 tests
- **Passed**: 67 (100%)
- **Failed**: 0
- **Regression**: 47/47 Sprint 1–3C tests passed with zero breaks.

### Real Screenshot Evidence (`evidence/sprint-04a/screenshots/`):
1. `01_login_page.png` — Login page with collapsible demo accounts
2. `02_admin_dashboard_identity.png` — Admin dashboard with identity context & badge
3. `03_security_analyst_navigation.png` — Security analyst navigation & active modules
4. `04_policy_author_semantic_policies.png` — Policy author semantic policies & draft interface
5. `05_auditor_read_only_view.png` — Auditor view with read-only badge & trace
6. `06_access_denied.png` — HTTP 403 Access Restricted page
7. `07_user_management.png` — Admin user management directory & role governance table
8. `08_swagger_authentication.png` — FastAPI Swagger UI authentication schemes & endpoints
9. `09_authenticated_api_request.png` — Authenticated API response schema
10. `10_docker_services.png` — Live running container stack

---

## 8. Known Limitations & Future Sprint Boundaries

1. **No External OAuth2/SAML/SSO**: Local JWT token authentication is used for the hackathon MVP.
2. **No Multi-Factor Authentication (MFA)**: MFA will be considered for future enterprise hardening.
3. **No Refresh Token Rotation**: Access tokens expire in 480 minutes (MVP).
4. **Dual-Control Approval (Sprint 4B)**: Formal multi-party approval workflows and four-eyes policy activation are explicitly deferred to Sprint 4B.
5. **Cryptographic Ledger (Sprint 5)**: Hash chaining and ledger tamper-evidence are deferred to future sprints.
