# Security Governance & RBAC Model

## Role Matrix (5 Roles, 32 Permissions)

| Role | Purpose | Write Access | Admin Access |
|---|---|---|---|
| `ADMIN` | System administrator | Full | Full |
| `SECURITY_ANALYST` | Operations analyst | Triage & Cases | None |
| `SECURITY_REVIEWER` | Senior reviewer | Dual Approvals | None |
| `COMPLIANCE_AUDITOR` | Auditor | Read-only Audit | None |
| `VIEWER` | Executive observer | Read-only | None |

## Maker-Checker Governance Invariant
Privileged actions (e.g. promoting detection rules, approving incident containment plans) require dual-operator authorization:
$$\text{Proposer User ID} \neq \text{Approver User ID}$$
If `proposer_id == approver_id`, the system enforces a self-approval rejection (HTTP 422 Unprocessable Entity).
