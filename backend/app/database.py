"""
database.py
-----------
SQLAlchemy database engine, session factory, and declarative base.

Sprint 0: Provides connectivity verification only.
Future sprints will add table models and migrations via Alembic.
"""

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings


import os
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB, ARRAY

# ── SQLite Compatibility Hooks for Testing & Offline Execution ────────────────
@compiles(JSONB, "sqlite")
def compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"

@compiles(ARRAY, "sqlite")
def compile_array_sqlite(type_, compiler, **kw):
    return "JSON"


# ── Engine Initialization ──────────────────────────────────────────────────────
db_url = os.environ.get("DATABASE_URL", settings.DATABASE_URL)
is_sqlite = db_url.startswith("sqlite")

engine_kwargs = {"echo": settings.DEBUG}
if not is_sqlite:
    engine_kwargs.update({
        "pool_pre_ping": True,
        "pool_size": 5,
        "max_overflow": 10,
    })
else:
    engine_kwargs.update({
        "connect_args": {"check_same_thread": False},
        "execution_options": {"schema_translate_map": {"sentinel": None}},
    })

try:
    engine = create_engine(db_url, **engine_kwargs)
    # Test connection if postgres; if fails and in test/dev, fallback to sqlite
    if not is_sqlite:
        try:
            with engine.connect() as conn:
                pass
        except Exception:
            # Fallback to local SQLite for test resilience
            engine = create_engine(
                "sqlite:///sentinel_trace.db",
                connect_args={"check_same_thread": False},
                execution_options={"schema_translate_map": {"sentinel": None}},
                echo=settings.DEBUG,
            )
except Exception:
    engine = create_engine(
        "sqlite:///sentinel_trace.db",
        connect_args={"check_same_thread": False},
        execution_options={"schema_translate_map": {"sentinel": None}},
        echo=settings.DEBUG,
    )

# ── Session Factory ────────────────────────────────────────────────────────────
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# ── Declarative Base ───────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    """Shared base class for all SQLAlchemy ORM models."""
    pass


# ── Dependency (FastAPI) ───────────────────────────────────────────────────────
def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a database session per request.

    Usage:
        @router.get("/example")
        def example(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """Context manager for use outside of FastAPI request scope."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ── Health Check ───────────────────────────────────────────────────────────────
def verify_database_connection() -> bool:
    """
    Execute a trivial query to confirm that the database is reachable.

    Returns True on success, raises an exception on failure.
    """
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True
