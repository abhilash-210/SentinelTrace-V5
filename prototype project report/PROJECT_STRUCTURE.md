# Complete Project Directory Structure

```
SENTINEL-TRACE/
├── backend/
│   ├── app/
│   │   ├── core/           # Auth, RBAC permissions, config
│   │   ├── models/         # 27 SQLAlchemy ORM models
│   │   ├── routers/        # 29 FastAPI REST routers
│   │   ├── schemas/        # Pydantic validation schemas
│   │   └── services/       # 25 domain logic services
│   ├── tests/              # Test suites (935 full regression tests)
│   └── sentinel_trace.db   # SQLite database
├── frontend/
│   ├── src/
│   │   ├── components/     # UI components (Header, Sidebar, Cards)
│   │   └── pages/          # 26 React Command Centers
│   ├── package.json        # Frontend dependencies
│   └── vite.config.js      # Vite build config
├── docs/                   # Architectural & sprint documentation
├── evidence/               # Sprint test execution evidence logs
├── scratch/                # Seed scripts (seed_sih_demo.py)
├── prototype project report/ # Complete 24-document report package
└── README.md               # Quickstart guide
```
