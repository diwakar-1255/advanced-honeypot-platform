CREATE OR REPLACE VIEW attacker_investigation_events AS
SELECT
    e.id,
    e.timestamp AS event_time,
    e.source_ip,
    e.service,
    e.event_type,
    COALESCE(NULLIF(e.attack_type, ''), 'Unknown') AS attack_type,
    COALESCE(NULLIF(e.username, ''), '-') AS username,
    e.method,
    e.path,
    e.command,
    e.user_agent,
    e.payload,
    COALESCE(e.risk_score, 0) AS risk_score,
    COALESCE(NULLIF(e.severity, ''), 'Low') AS severity,
    COALESCE(NULLIF(e.mitre_id, ''), '-') AS mitre_id,
    COALESCE(NULLIF(e.mitre_tactic, ''), '-') AS mitre_tactic,
    COALESCE(NULLIF(e.mitre_technique, ''), '-') AS mitre_technique,
    COALESCE(
        NULLIF(e.raw_log->>'country', ''),
        NULLIF(e.raw_log->>'geo_country', ''),
        CASE
            WHEN e.source_ip IN ('127.0.0.1', '::1', 'localhost') THEN 'Localhost'
            WHEN e.source_ip LIKE '10.%'
              OR e.source_ip LIKE '172.%'
              OR e.source_ip LIKE '192.168.%' THEN 'Private/Internal'
            ELSE 'Unknown'
        END
    ) AS country,
    COALESCE(
        NULLIF(e.raw_log->>'city', ''),
        NULLIF(e.raw_log->>'geo_city', ''),
        CASE
            WHEN e.source_ip IN ('127.0.0.1', '::1', 'localhost') THEN 'Local Machine'
            WHEN e.source_ip LIKE '10.%'
              OR e.source_ip LIKE '172.%'
              OR e.source_ip LIKE '192.168.%' THEN 'Internal Network'
            ELSE 'Unknown'
        END
    ) AS city,
    COALESCE(
        NULLIF(e.raw_log->>'asn', ''),
        NULLIF(e.raw_log->>'as_org', ''),
        NULLIF(e.raw_log->>'org', ''),
        'Unknown'
    ) AS asn,
    e.raw_log
FROM events e;

CREATE OR REPLACE VIEW attacker_investigation_summary AS
SELECT
    source_ip,
    MAX(country) AS country,
    MAX(city) AS city,
    MAX(asn) AS asn,
    MIN(event_time) AS first_seen,
    MAX(event_time) AS last_seen,
    COUNT(*) AS total_attacks,
    COUNT(*) FILTER (WHERE service = 'SSH') AS ssh_attacks,
    COUNT(*) FILTER (WHERE service = 'FTP') AS ftp_attacks,
    COUNT(*) FILTER (WHERE service IN ('HTTP', 'HTTPS')) AS web_attacks,
    COUNT(DISTINCT service) AS services_touched,
    COUNT(DISTINCT attack_type) AS attack_type_count,
    STRING_AGG(DISTINCT attack_type, ', ' ORDER BY attack_type) AS attack_types,
    STRING_AGG(DISTINCT mitre_id, ', ' ORDER BY mitre_id) FILTER (WHERE mitre_id <> '-') AS mitre_techniques,
    MAX(risk_score) AS max_risk_score,
    CASE
        WHEN MAX(risk_score) >= 90 THEN 'Critical'
        WHEN MAX(risk_score) >= 70 THEN 'High'
        WHEN MAX(risk_score) >= 40 THEN 'Medium'
        ELSE 'Low'
    END AS investigation_severity
FROM attacker_investigation_events
GROUP BY source_ip;

CREATE OR REPLACE VIEW attacker_investigation_timeline AS
SELECT
    event_time,
    source_ip,
    country,
    service,
    event_type,
    attack_type,
    username,
    method,
    path,
    command,
    mitre_id,
    mitre_technique,
    risk_score,
    severity,
    CASE
        WHEN service IN ('HTTP', 'HTTPS') THEN
            CONCAT_WS(' ', method, path)
        WHEN service = 'SSH' THEN
            COALESCE(command, event_type)
        WHEN service = 'FTP' THEN
            COALESCE(path, command, event_type)
        ELSE
            COALESCE(event_type, attack_type)
    END AS attacker_action
FROM attacker_investigation_events;

CREATE OR REPLACE VIEW attacker_web_session_replay AS
SELECT
    event_time,
    source_ip,
    country,
    method,
    path,
    user_agent,
    attack_type,
    risk_score,
    severity,
    ROW_NUMBER() OVER (
        PARTITION BY source_ip
        ORDER BY event_time
    ) AS sequence_no
FROM attacker_investigation_events
WHERE service IN ('HTTP', 'HTTPS')
ORDER BY source_ip, event_time;

CREATE INDEX IF NOT EXISTS idx_events_investigation_source_time
ON events(source_ip, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_investigation_attack_type
ON events(attack_type);

CREATE INDEX IF NOT EXISTS idx_events_investigation_mitre
ON events(mitre_id);

CREATE INDEX IF NOT EXISTS idx_events_investigation_risk
ON events(risk_score);
