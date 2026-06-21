CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS attackers (
    id SERIAL PRIMARY KEY,
    source_ip VARCHAR(100) UNIQUE NOT NULL,
    country VARCHAR(100),
    city VARCHAR(100),
    region VARCHAR(100),
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    isp VARCHAR(255),
    asn VARCHAR(100),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_events INT DEFAULT 0,
    risk_score INT DEFAULT 0,
    severity VARCHAR(50) DEFAULT 'Low'
);

CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    event_id UUID DEFAULT uuid_generate_v4(),
    source_ip VARCHAR(100),
    service VARCHAR(50),
    event_type VARCHAR(100),
    source_port INT,
    destination_port INT,
    username TEXT,
    password TEXT,
    command TEXT,
    method VARCHAR(20),
    path TEXT,
    user_agent TEXT,
    payload TEXT,
    attack_type VARCHAR(100),
    risk_score INT DEFAULT 0,
    severity VARCHAR(50) DEFAULT 'Low',
    raw_log JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    source_ip VARCHAR(100),
    title TEXT,
    severity VARCHAR(50),
    risk_score INT,
    description TEXT,
    status VARCHAR(50) DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_intel (
    id SERIAL PRIMARY KEY,
    source_ip VARCHAR(100),
    country VARCHAR(100),
    city VARCHAR(100),
    asn VARCHAR(100),
    isp VARCHAR(255),
    abuse_score INT,
    vt_score INT,
    is_tor BOOLEAN DEFAULT false,
    is_proxy BOOLEAN DEFAULT false,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
