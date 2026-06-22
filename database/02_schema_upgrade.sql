-- Advanced honeypot schema upgrade

ALTER TABLE events
ADD COLUMN IF NOT EXISTS mitre_id TEXT,
ADD COLUMN IF NOT EXISTS mitre_tactic TEXT,
ADD COLUMN IF NOT EXISTS mitre_technique TEXT,
ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS raw_log TEXT;

ALTER TABLE attackers
ADD COLUMN IF NOT EXISTS reputation_score INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS reputation_level TEXT DEFAULT 'Unknown',
ADD COLUMN IF NOT EXISTS is_cloud_or_hosting BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS reputation_reason TEXT,
ADD COLUMN IF NOT EXISTS last_reputation_update TIMESTAMP;

CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    incident_key TEXT UNIQUE,
    source_ip TEXT,
    incident_type TEXT,
    severity TEXT,
    risk_score INTEGER DEFAULT 0,
    event_count INTEGER DEFAULT 0,
    services TEXT[],
    attack_types TEXT[],
    mitre_ids TEXT[],
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    summary TEXT,
    status TEXT DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ssh_sessions (
    id SERIAL PRIMARY KEY,
    session_key TEXT UNIQUE,
    source_ip TEXT,
    username TEXT,
    severity TEXT,
    risk_score INTEGER DEFAULT 0,
    event_count INTEGER DEFAULT 0,
    command_count INTEGER DEFAULT 0,
    mitre_ids TEXT[],
    started_at TIMESTAMP,
    ended_at TIMESTAMP,
    timeline JSONB,
    summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS malware_samples (
    id SERIAL PRIMARY KEY,
    source_ip TEXT,
    service TEXT,
    original_path TEXT,
    local_path TEXT,
    file_name TEXT,
    file_size BIGINT,
    sha256 TEXT UNIQUE,
    yara_matches TEXT[],
    suspicious_strings TEXT[],
    risk_score INTEGER DEFAULT 0,
    verdict TEXT DEFAULT 'unknown',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    username TEXT,
    role TEXT,
    action TEXT NOT NULL,
    source_ip TEXT,
    target TEXT,
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_attack_type ON events(attack_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_mitre_id ON events(mitre_id);
CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_ssh_sessions_source_ip ON ssh_sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_malware_samples_sha256 ON malware_samples(sha256);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
