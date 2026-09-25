"""
config.py
---------
Centralised configuration for SENTINEL-TRACE backend.

All values are loaded from environment variables (or .env file in development).
Never hardcode secrets in this file.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── Application ────────────────────────────────────────────────────────────
    APP_NAME: str = "sentinel-trace-backend"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"
    DEBUG: bool = False

    # ── Database ───────────────────────────────────────────────────────────────
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "sentinel_trace"
    POSTGRES_USER: str = "sentinel"
    POSTGRES_PASSWORD: str = "changeme"

    @property
    def DATABASE_URL(self) -> str:
        """Construct the SQLAlchemy-compatible PostgreSQL connection URL."""
        import os
        return os.environ.get("DATABASE_URL") or (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # ── Security (Sprint 1+) ───────────────────────────────────────────────────
    SECRET_KEY: str = "CHANGE_THIS_TO_A_RANDOM_SECRET_KEY_BEFORE_PRODUCTION"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # ── CORS ───────────────────────────────────────────────────────────────────
    ALLOWED_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


# Single shared instance — import this everywhere
settings = Settings()
