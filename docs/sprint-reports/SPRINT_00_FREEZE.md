# Sprint 0 Freeze Record

**Sprint:** Sprint 0 — Project Foundation  
**Status:** PASS  
**Freeze Date:** 2026-09-06  
**Architecture Version:** SentinelTrace V5  

---

## Frozen Components

The following foundation components are finalized and frozen for Sprint 0:

- **FastAPI Project Foundation:**
  - `backend/app/main.py` (application lifespan, CORS, exception handling, root info endpoint)
  - `backend/app/config.py` (Pydantic Settings with env var validation)
  - `backend/app/database.py` (SQLAlchemy 2.0 engine, SessionLocal, ping connection check)
  - `backend/app/routers/health.py` (`/health` and `/` endpoints)
  - Modular package structure (`models/`, `schemas/`, `services/`, `routers/`)

- **React Dashboard Foundation:**
  - `frontend/src/App.jsx` (layout structure, navigation state)
  - `frontend/src/components/Sidebar.jsx` (10 cybersecurity navigation items with future sprint badges)
  - `frontend/src/components/StatusCard.jsx` (pillar and status display components)
  - `frontend/src/pages/Dashboard.jsx` (architecture pillars, status cards, sprint roadmap banner)
  - Tailwind CSS dark-mode cybersecurity theme and responsive grid layout

- **PostgreSQL Configuration:**
  - `database/init/01_init.sql` (schema initialization, grants, search_path configuration)
  - Persistent volume configuration (`sentinel-trace-postgres-data`)

- **Docker Compose Infrastructure:**
  - `docker-compose.yml` (multi-stage builds, inter-service networking, strict healthcheck dependency chain)
  - `backend/Dockerfile` (Python 3.11-slim, multi-worker uvicorn with watchfiles reload)
  - `frontend/Dockerfile` (multi-stage Node 20 builder -> Nginx 1.25 runner)
  - `frontend/nginx.conf` (SPA routing fallback, gzip compression, dual IPv4/IPv6 listen)
  - `backend/.dockerignore`

- **Environment Configuration:**
  - `.env.example` (template with clear variable documentation)
  - `.env` (gitignored local development configuration)
  - `.gitignore` (excludes secrets, virtualenvs, build artifacts, IDE configs)

- **Evidence Collection Structure:**
  - `evidence/sprint-00/logs/` (runtime HTTP response logs, container status, log summary)
  - `evidence/sprint-00/screenshots/` (genuine headless Chromium runtime screenshot captures)
  - `evidence/sprint-00/verification/` (machine-readable verification status)

---

## Explicitly Not Implemented (Out of Scope for Sprint 0)

The following components are intentionally deferred to future sprints according to the SentinelTrace V5 architecture roadmap:

- Evidence Vault
- Log ingestion
- SHA-256 hashing
- Normalization
- OCSF mapping
- Semantic Policy Registry
- Authentication
- Dual control
- Cryptographic ledger
- STIG

---

## Next Authorized Sprint

**Sprint 1 — Evidence Vault and Secure Log Ingestion**
