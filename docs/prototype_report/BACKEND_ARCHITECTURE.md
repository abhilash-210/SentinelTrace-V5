# Backend Architecture Reference

## Technology Foundation
- **Framework**: FastAPI 0.109+
- **ORM**: SQLAlchemy 2.0+ (SQLite database with `sentinel` schema isolation)
- **Validation**: Pydantic v2 schemas
- **Authentication**: OAuth2 Password Bearer with JWT (HS256)

## Directory Layout (`backend/app/`)
- `main.py`: Application entry point, CORS middleware, router registration.
- `database.py`: SQLAlchemy session maker (`SessionLocal`), engine configuration.
- `models/`: 27 ORM models representing the complete security intelligence domain.
- `routers/`: 29 FastAPI routers handling REST requests.
- `services/`: 25 core business logic services.
- `core/`: Auth helpers, RBAC permission definitions, security utilities.
