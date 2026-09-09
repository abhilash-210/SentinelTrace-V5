-- ============================================================
-- SENTINEL-TRACE — PostgreSQL Initialization Script
-- Sprint 0: Project Foundation
-- ============================================================
-- This script runs automatically when the postgres container
-- starts for the first time (docker-entrypoint-initdb.d).
-- ============================================================

-- Verify connection (used by /health endpoint)
SELECT version();

-- Create application schema (all tables will live here)
CREATE SCHEMA IF NOT EXISTS sentinel;

-- Grant privileges to the application user
-- The user is created by the POSTGRES_USER env var in docker-compose
GRANT ALL PRIVILEGES ON SCHEMA sentinel TO sentinel;

-- Sprint 0 placeholder comment
-- Future sprints will add CREATE TABLE statements here via Alembic migrations
-- DO NOT manually add tables here after Sprint 1.

-- Log successful initialization
DO $$
BEGIN
    RAISE NOTICE 'SENTINEL-TRACE database initialized successfully.';
    RAISE NOTICE 'Schema: sentinel';
    RAISE NOTICE 'Sprint: 0 — Project Foundation';
END $$;
