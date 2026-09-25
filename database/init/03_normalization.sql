-- ============================================================
-- SENTINEL-TRACE — PostgreSQL Normalization & Source Profiles
-- Sprint 2: Source Parsing & OCSF-Aligned Normalization
-- ============================================================

CREATE SCHEMA IF NOT EXISTS sentinel;

-- Source Profiles Table
CREATE TABLE IF NOT EXISTS sentinel.source_profiles (
    id SERIAL PRIMARY KEY,
    source_profile_id VARCHAR(64) UNIQUE NOT NULL,
    profile_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(100) NOT NULL,
    supported_format VARCHAR(50) NOT NULL,
    parser_type VARCHAR(50) NOT NULL,
    version VARCHAR(32) NOT NULL DEFAULT 'v1.0.0',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_source_profiles_source_profile_id 
    ON sentinel.source_profiles (source_profile_id);

CREATE INDEX IF NOT EXISTS ix_source_profiles_source_type 
    ON sentinel.source_profiles (source_type);

-- Normalized Events Table
CREATE TABLE IF NOT EXISTS sentinel.normalized_events (
    id SERIAL PRIMARY KEY,
    normalized_event_id VARCHAR(64) UNIQUE NOT NULL,
    original_event_id VARCHAR(64) NOT NULL,
    class_uid INTEGER NOT NULL DEFAULT 0,
    class_name VARCHAR(100) NOT NULL,
    activity_id INTEGER NOT NULL DEFAULT 0,
    activity_name VARCHAR(100) NOT NULL,
    event_time TIMESTAMP WITH TIME ZONE,
    source_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(100) NOT NULL,
    action VARCHAR(50),
    src_ip VARCHAR(45),
    src_port INTEGER,
    dst_ip VARCHAR(45),
    dst_port INTEGER,
    protocol VARCHAR(30),
    severity VARCHAR(30),
    user_name VARCHAR(255),
    hostname VARCHAR(255),
    process_name VARCHAR(255),
    process_id INTEGER,
    raw_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    parser_name VARCHAR(100) NOT NULL,
    parser_version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
    source_profile_id VARCHAR(64),
    normalization_status VARCHAR(50) NOT NULL DEFAULT 'NORMALIZED',
    normalization_confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    confidence_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    normalized_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_normalized_events_normalized_id 
    ON sentinel.normalized_events (normalized_event_id);

CREATE INDEX IF NOT EXISTS ix_normalized_events_original_id 
    ON sentinel.normalized_events (original_event_id);

CREATE INDEX IF NOT EXISTS ix_normalized_events_class_name 
    ON sentinel.normalized_events (class_name);

CREATE INDEX IF NOT EXISTS ix_normalized_events_status 
    ON sentinel.normalized_events (normalization_status);

CREATE INDEX IF NOT EXISTS ix_normalized_events_normalized_at 
    ON sentinel.normalized_events (normalized_at DESC);

-- Permissions
GRANT ALL PRIVILEGES ON TABLE sentinel.source_profiles TO sentinel;
GRANT USAGE, SELECT ON SEQUENCE sentinel.source_profiles_id_seq TO sentinel;
GRANT ALL PRIVILEGES ON TABLE sentinel.normalized_events TO sentinel;
GRANT USAGE, SELECT ON SEQUENCE sentinel.normalized_events_id_seq TO sentinel;
