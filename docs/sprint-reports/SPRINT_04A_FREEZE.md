# Sprint 4A Freeze Declaration — Identity & Role-Based Access Control

**Project**: SENTINEL-TRACE (SIH 2026 Prototype)  
**Architecture Version**: V5  
**Sprint**: Sprint 4A (Identity & RBAC)  
**Date of Freeze**: 2026-09-06  
**Status**: **FROZEN & VERIFIED (PASS)**

---

## 1. Freeze Scope

Sprint 4A is officially **FROZEN**. All code, database schemas, API contracts, RBAC matrices, and user interfaces developed under this sprint are locked against regressions.

### Completed & Frozen Capabilities:
1. **User Identity Data Model** (`sentinel.users` table with Alembic migration `d4e5f6a7b8c9`).
2. **Secure Credential Storage** using Bcrypt password hashing (`passlib`).
3. **JWT Access Tokens** (`python-jose`) with configurable expiration and secure bearer headers.
4. **Current User Dependency Injection** (`get_current_user`, `get_current_active_user`).
5. **Centralized RBAC Service** (`app/core/rbac.py`) with 6 distinct roles (`ADMIN`, `SECURITY_ANALYST`, `POLICY_AUTHOR`, `POLICY_REVIEWER`, `AUDITOR`, `VIEWER`).
6. **Authorization Dependency Layer** (`require_permission`, `require_role`) returning HTTP 401 for unauthenticated requests and HTTP 403 for unauthorized requests.
7. **Protected API Endpoints** across Evidence Vault, Normalization, Semantic Policies, Semantic Interpretation, and Admin User Management.
8. **Admin User Management REST Endpoints** (`GET /users`, `GET /users/{id}`, `POST /users`, `PATCH /users/{id}`).
9. **Role-Aware React Frontend**:
   - `/login` page with collapsible development demo account quick selector.
   - Top-navigation role badge and user identity profile menu.
   - Dynamic sidebar navigation filtered by role capability.
   - `/profile` user identity and granted permission viewer.
   - `/users` admin-only identity governance table and registration modal.
   - `AccessRestricted` (HTTP 403) UI component.
10. **Test Coverage & Regression Baseline**:
   - 47/47 Sprint 1–3C tests pass without regression.
   - 20/20 Sprint 4A identity and RBAC tests pass.
   - Total test suite: 67/67 PASS (0 Failed, 0 Skipped).

---

## 2. Strict Boundary & Non-Goals

The following features belong strictly to future sprints and are **NOT** implemented in Sprint 4A:
- **Sprint 4B**: Multi-party dual control, policy approval/rejection workflows, four-eyes enforcement, and activation transitions.
- **Sprint 5**: Cryptographic governance ledger, hash chaining, digital signatures, and Merkle proofs.

---

## 3. Ready for Sprint 4B

With authenticated identity and RBAC verified, the foundation for **WHO performed an action** is fully operational. The system is ready to proceed to Sprint 4B (**WHO can approve actions**).
