from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import psycopg2
import psycopg2.extras
import os
import hashlib
import ipaddress
import urllib.request
import urllib.parse
import json
import time
from email_alerts import send_honeypot_email_alert

app = FastAPI(title="Professional Honeypot SOC API with GeoIP Enrichment")


if not os.getenv("POSTGRES_PASSWORD"):
    raise RuntimeError("POSTGRES_PASSWORD is not set")

DB_CONFIG = {
    "dbname": os.getenv("POSTGRES_DB", "honeypotdb"),
    "user": os.getenv("POSTGRES_USER", "honeypot"),
    "password": os.getenv("POSTGRES_PASSWORD"),
    "host": os.getenv("POSTGRES_HOST", "postgres"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
}

SEVERITY_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}

ALERT_THRESHOLD = os.getenv("ALERT_MIN_SEVERITY", "Medium")
GEOIP_PROVIDER_URL = os.getenv("GEOIP_PROVIDER_URL", "http://ip-api.com/json")
GEOIP_TIMEOUT = int(os.getenv("GEOIP_TIMEOUT", "5"))

_GEO_CACHE = {}
_SCHEMA_READY = False


class HoneypotEvent(BaseModel):
    source_ip: str
    service: str
    event_type: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    user_agent: Optional[str] = None
    payload: Optional[Any] = None
    attack_type: Optional[str] = None
    risk_score: int = 0
    severity: str = "Low"
    raw_log: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


def ensure_schema():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                ALTER TABLE attackers ADD COLUMN IF NOT EXISTS country VARCHAR(100);
                ALTER TABLE attackers ADD COLUMN IF NOT EXISTS city VARCHAR(100);
                ALTER TABLE attackers ADD COLUMN IF NOT EXISTS isp VARCHAR(255);
                ALTER TABLE attackers ADD COLUMN IF NOT EXISTS asn VARCHAR(255);
            """)

            cur.execute("""
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS incident_id VARCHAR(50);
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS alert_type VARCHAR(100);
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS service VARCHAR(50);
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS event_type VARCHAR(100);
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS attack_type VARCHAR(100);
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS recommendation TEXT;
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique TEXT;
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(100);
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS occurrence_count INT DEFAULT 1;
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
                ALTER TABLE alerts ADD COLUMN IF NOT EXISTS raw_context JSONB;
            """)

            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_fingerprint
                ON alerts(fingerprint);
            """)

        conn.commit()
    finally:
        conn.close()


def ensure_schema_once():
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    ensure_schema()
    _SCHEMA_READY = True


@app.on_event("startup")
def startup_check():
    try:
        ensure_schema_once()
        print("Database schema check completed.")
    except Exception as exc:
        print("Database schema check skipped at startup:", exc)


def severity_from_score(score: int) -> str:
    if score >= 81:
        return "Critical"
    if score >= 61:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"


def normalize_severity(event: HoneypotEvent) -> str:
    calculated = severity_from_score(event.risk_score)
    if SEVERITY_RANK.get(calculated, 1) > SEVERITY_RANK.get(event.severity, 1):
        return calculated
    return event.severity


def event_extra(event: HoneypotEvent) -> Dict[str, Any]:
    extra = {}

    try:
        extra.update(getattr(event, "__pydantic_extra__", {}) or {})
    except Exception:
        pass

    try:
        model_extra = getattr(event, "model_extra", None)
        if isinstance(model_extra, dict):
            extra.update(model_extra)
    except Exception:
        pass

    return extra


def event_to_dict(event: HoneypotEvent) -> Dict[str, Any]:
    try:
        data = event.model_dump(exclude_none=True)
    except Exception:
        data = event.dict(exclude_none=True)

    data.update(event_extra(event))
    return data


def payload_to_text(payload: Any) -> Optional[str]:
    if payload is None:
        return None

    if isinstance(payload, str):
        return payload

    try:
        return json.dumps(payload, ensure_ascii=False)
    except Exception:
        return str(payload)


def get_headers_from_event(event: HoneypotEvent) -> Dict[str, Any]:
    headers = {}

    if isinstance(event.raw_log, dict):
        raw_headers = event.raw_log.get("headers")
        if isinstance(raw_headers, dict):
            headers.update(raw_headers)

    extra_headers = event_extra(event).get("headers")
    if isinstance(extra_headers, dict):
        headers.update(extra_headers)

    return {str(k).lower(): v for k, v in headers.items()}


def clean_ip_candidate(value: Any) -> Optional[str]:
    if value is None:
        return None

    value = str(value).strip()
    if not value:
        return None

    if "," in value:
        value = value.split(",")[0].strip()

    if value.startswith("[") and "]" in value:
        value = value.split("]")[0].replace("[", "").strip()
    elif value.count(":") == 1 and "." in value:
        value = value.split(":")[0].strip()

    return value.strip("\"' ") or None


def valid_ip(value: Any):
    cleaned = clean_ip_candidate(value)
    if not cleaned:
        return None

    try:
        return ipaddress.ip_address(cleaned)
    except Exception:
        return None


def extract_candidate_ips(event: HoneypotEvent) -> List[str]:
    headers = get_headers_from_event(event)
    candidates = []

    header_keys = [
        "cf-connecting-ip",
        "true-client-ip",
        "x-real-ip",
        "x-forwarded-for",
        "forwarded",
        "x-client-ip",
    ]

    for key in header_keys:
        value = headers.get(key)
        if not value:
            continue

        if key == "forwarded":
            parts = str(value).split(";")
            for part in parts:
                part = part.strip()
                if part.lower().startswith("for="):
                    candidates.append(part.split("=", 1)[1].strip())
        else:
            for item in str(value).split(","):
                candidates.append(item.strip())

    candidates.append(event.source_ip)

    valid_candidates = []
    seen = set()

    for item in candidates:
        ip_obj = valid_ip(item)
        if ip_obj and str(ip_obj) not in seen:
            valid_candidates.append(str(ip_obj))
            seen.add(str(ip_obj))

    return valid_candidates


def choose_best_source_ip(event: HoneypotEvent) -> str:
    candidates = extract_candidate_ips(event)

    for candidate in candidates:
        ip_obj = ipaddress.ip_address(candidate)
        if not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return candidate

    if candidates:
        return candidates[0]

    return event.source_ip


def private_ip_details(source_ip: str) -> Optional[Dict[str, str]]:
    try:
        ip_obj = ipaddress.ip_address(source_ip)
    except Exception:
        return {
            "country": "Invalid IP",
            "city": "Invalid IP",
            "isp": "Invalid IP",
            "asn": "Invalid IP"
        }

    if ip_obj.is_loopback:
        return {
            "country": "Localhost",
            "city": "Local Machine",
            "isp": "Loopback Interface",
            "asn": "Local"
        }

    if ip_obj.is_link_local:
        return {
            "country": "Link-Local/Internal",
            "city": "Local Network Segment",
            "isp": "Link-Local Address",
            "asn": "Private"
        }

    if ip_obj.is_unspecified:
        return {
            "country": "Unspecified",
            "city": "Unspecified",
            "isp": "Unspecified Address",
            "asn": "None"
        }

    if ip_obj.version == 4:
        docker_networks = [
            ipaddress.ip_network("172.17.0.0/16"),
            ipaddress.ip_network("172.18.0.0/16"),
            ipaddress.ip_network("172.19.0.0/16"),
            ipaddress.ip_network("172.20.0.0/16"),
            ipaddress.ip_network("172.21.0.0/16"),
            ipaddress.ip_network("172.22.0.0/16"),
            ipaddress.ip_network("172.23.0.0/16"),
            ipaddress.ip_network("172.24.0.0/16"),
            ipaddress.ip_network("172.25.0.0/16"),
            ipaddress.ip_network("172.26.0.0/16"),
            ipaddress.ip_network("172.27.0.0/16"),
            ipaddress.ip_network("172.28.0.0/16"),
            ipaddress.ip_network("172.29.0.0/16"),
            ipaddress.ip_network("172.30.0.0/16"),
            ipaddress.ip_network("172.31.0.0/16"),
        ]

        if any(ip_obj in network for network in docker_networks):
            return {
                "country": "Private/Internal",
                "city": "Docker Bridge Network",
                "isp": "Docker Bridge / Local Host",
                "asn": "RFC1918 Private"
            }

        if ip_obj in ipaddress.ip_network("10.0.0.0/8"):
            return {
                "country": "Private/Internal",
                "city": "Private LAN",
                "isp": "Internal Network 10.0.0.0/8",
                "asn": "RFC1918 Private"
            }

        if ip_obj in ipaddress.ip_network("172.16.0.0/12"):
            return {
                "country": "Private/Internal",
                "city": "Private LAN",
                "isp": "Internal Network 172.16.0.0/12",
                "asn": "RFC1918 Private"
            }

        if ip_obj in ipaddress.ip_network("192.168.0.0/16"):
            return {
                "country": "Private/Internal",
                "city": "Private LAN",
                "isp": "Internal Network 192.168.0.0/16",
                "asn": "RFC1918 Private"
            }

    if ip_obj.is_private:
        return {
            "country": "Private/Internal",
            "city": "Private Network",
            "isp": "Internal Network",
            "asn": "Private"
        }

    if ip_obj.is_reserved:
        return {
            "country": "Reserved",
            "city": "Reserved Address Space",
            "isp": "Reserved Address",
            "asn": "Reserved"
        }

    if ip_obj.is_multicast:
        return {
            "country": "Multicast",
            "city": "Multicast Address Space",
            "isp": "Multicast Address",
            "asn": "Multicast"
        }

    return None


def lookup_public_ip(source_ip: str) -> Dict[str, str]:
    now = time.time()
    cached = _GEO_CACHE.get(source_ip)

    if cached and now - cached.get("time", 0) < 86400:
        return cached["data"]

    fields = "status,message,country,city,isp,as,asname,query"
    url = f"{GEOIP_PROVIDER_URL}/{urllib.parse.quote(source_ip)}?fields={fields}"

    try:
        with urllib.request.urlopen(url, timeout=GEOIP_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8"))

        if data.get("status") == "success":
            result = {
                "country": data.get("country") or "Unknown",
                "city": data.get("city") or "Unknown",
                "isp": data.get("isp") or data.get("asname") or "Unknown",
                "asn": data.get("as") or data.get("asname") or "Unknown",
            }
        else:
            result = {
                "country": "Unknown",
                "city": "Unknown",
                "isp": data.get("message") or "GeoIP lookup failed",
                "asn": "Unknown",
            }

    except Exception as exc:
        result = {
            "country": "Lookup Failed",
            "city": "Lookup Failed",
            "isp": f"GeoIP error: {str(exc)[:80]}",
            "asn": "Lookup Failed",
        }

    _GEO_CACHE[source_ip] = {
        "time": now,
        "data": result
    }

    return result


def enrich_ip(source_ip: str) -> Dict[str, str]:
    private_details = private_ip_details(source_ip)

    if private_details:
        return private_details

    return lookup_public_ip(source_ip)


def map_mitre(attack_type: Optional[str], event_type: Optional[str]) -> str:
    attack_type = attack_type or ""
    event_type = event_type or ""

    mapping = {
        "Credential Attack": "T1110 - Brute Force",
        "FTP Login Attempt": "T1110 - Brute Force",
        "FTP Probe": "T1046 - Network Service Discovery",
        "SQL Injection": "T1190 - Exploit Public-Facing Application",
        "XSS": "T1190 - Exploit Public-Facing Application",
        "Path Traversal": "T1190 - Exploit Public-Facing Application",
        "Command Injection": "T1059 - Command and Scripting Interpreter",
        "Scanner": "T1595 - Active Scanning",
        "Sensitive File Access Attempt": "T1005 - Data from Local System",
        "File Upload Attempt": "T1105 - Ingress Tool Transfer",
        "Web Probe": "T1595 - Active Scanning",
    }

    if attack_type in mapping:
        return mapping[attack_type]

    if "login" in event_type.lower():
        return "T1110 - Brute Force"

    return "Unmapped"


def recommendation_for(event: HoneypotEvent, severity: str) -> str:
    attack_type = event.attack_type or "Unknown"

    if attack_type in ["SQL Injection", "XSS", "Path Traversal", "Command Injection"]:
        return (
            "Review web application logs, validate input handling, check WAF rules, "
            "and monitor the source IP for repeated exploitation attempts."
        )

    if attack_type in ["Credential Attack", "FTP Login Attempt"]:
        return (
            "Monitor repeated login attempts, enforce account lockout policies, "
            "review brute-force indicators, and block the source IP if repeated."
        )

    if attack_type == "File Upload Attempt":
        return (
            "Treat this as high risk. Inspect uploaded file metadata in an isolated lab, "
            "block the source IP, and check for web shell or malware upload behavior."
        )

    if attack_type == "Sensitive File Access Attempt":
        return (
            "Check whether the attacker attempted to access backup, configuration, "
            "or credential files. Ensure sensitive files are not publicly exposed."
        )

    if attack_type == "Scanner":
        return (
            "Classify as reconnaissance. Monitor for follow-up exploitation attempts "
            "from the same IP, ASN, or user-agent."
        )

    if severity in ["High", "Critical"]:
        return (
            "Investigate source IP, review related events, check firewall logs, "
            "and consider temporary blocking if activity continues."
        )

    return "Store event for monitoring and correlate with future attacker activity."


def alert_title(event: HoneypotEvent, severity: str) -> str:
    attack_type = event.attack_type or event.event_type
    return f"{severity} {event.service} Alert: {attack_type}"


def build_fingerprint(event: HoneypotEvent) -> str:
    base = "|".join([
        event.source_ip or "",
        event.service or "",
        event.attack_type or "",
        event.event_type or "",
        event.username or "",
        event.path or "",
    ])

    return hashlib.sha256(base.encode()).hexdigest()[:24]


def build_description(event: HoneypotEvent, severity: str, mitre: str, geo: Dict[str, str]) -> str:
    parts = [
        f"Source IP: {event.source_ip}",
        f"Country: {geo.get('country', 'Unknown')}",
        f"City: {geo.get('city', 'Unknown')}",
        f"ISP: {geo.get('isp', 'Unknown')}",
        f"ASN: {geo.get('asn', 'Unknown')}",
        f"Service: {event.service}",
        f"Event Type: {event.event_type}",
        f"Attack Type: {event.attack_type or 'Unknown'}",
        f"Risk Score: {event.risk_score}",
        f"Severity: {severity}",
        f"MITRE: {mitre}",
    ]

    if event.username:
        parts.append(f"Username: {event.username}")

    if event.password:
        parts.append("Password Captured: ****")

    if event.command:
        parts.append(f"Command: {event.command}")

    if event.path:
        parts.append(f"Path: {event.path}")

    if event.user_agent:
        parts.append(f"User-Agent: {event.user_agent}")

    payload_text = payload_to_text(event.payload)

    if payload_text:
        parts.append(f"Payload: {payload_text[:500]}")

    return "\n".join(parts)


def normalize_event_before_store(event: HoneypotEvent) -> Dict[str, str]:
    best_ip = choose_best_source_ip(event)
    event.source_ip = best_ip

    extra = event_extra(event)

    if not event.path:
        url_value = extra.get("url")
        if url_value:
            try:
                event.path = urllib.parse.urlparse(str(url_value)).path
            except Exception:
                pass

    if not event.user_agent:
        headers = get_headers_from_event(event)
        ua = headers.get("user-agent")
        if ua:
            event.user_agent = str(ua)

    geo = enrich_ip(event.source_ip)

    return geo


def update_attacker(conn, event: HoneypotEvent, severity: str, geo: Dict[str, str]):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO attackers (
                source_ip, country, city, isp, asn,
                first_seen, last_seen, total_events, risk_score, severity
            )
            VALUES (
                %s, %s, %s, %s, %s,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, %s, %s
            )
            ON CONFLICT (source_ip)
            DO UPDATE SET
                last_seen = CURRENT_TIMESTAMP,
                total_events = attackers.total_events + 1,
                risk_score = GREATEST(attackers.risk_score, EXCLUDED.risk_score),
                severity = CASE
                    WHEN GREATEST(attackers.risk_score, EXCLUDED.risk_score) >= 81 THEN 'Critical'
                    WHEN GREATEST(attackers.risk_score, EXCLUDED.risk_score) >= 61 THEN 'High'
                    WHEN GREATEST(attackers.risk_score, EXCLUDED.risk_score) >= 31 THEN 'Medium'
                    ELSE 'Low'
                END,
                country = CASE
                    WHEN EXCLUDED.country NOT IN ('Unknown', 'Lookup Failed')
                    THEN EXCLUDED.country
                    ELSE COALESCE(NULLIF(attackers.country, ''), EXCLUDED.country)
                END,
                city = CASE
                    WHEN EXCLUDED.city NOT IN ('Unknown', 'Lookup Failed')
                    THEN EXCLUDED.city
                    ELSE COALESCE(NULLIF(attackers.city, ''), EXCLUDED.city)
                END,
                isp = CASE
                    WHEN EXCLUDED.isp NOT IN ('Unknown', 'Lookup Failed')
                    THEN EXCLUDED.isp
                    ELSE COALESCE(NULLIF(attackers.isp, ''), EXCLUDED.isp)
                END,
                asn = CASE
                    WHEN EXCLUDED.asn NOT IN ('Unknown', 'Lookup Failed')
                    THEN EXCLUDED.asn
                    ELSE COALESCE(NULLIF(attackers.asn, ''), EXCLUDED.asn)
                END;
            """,
            (
                event.source_ip,
                geo.get("country", "Unknown"),
                geo.get("city", "Unknown"),
                geo.get("isp", "Unknown"),
                geo.get("asn", "Unknown"),
                event.risk_score,
                severity
            )
        )


def insert_event(conn, event: HoneypotEvent, severity: str, geo: Dict[str, str]):
    raw_log = event.raw_log if isinstance(event.raw_log, dict) else {}
    raw_log = {**raw_log, **event_extra(event), "geo": geo}

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO events (
                source_ip, service, event_type, source_port, destination_port,
                username, password, command, method, path, user_agent, payload,
                attack_type, risk_score, severity, raw_log
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (
                event.source_ip,
                event.service,
                event.event_type,
                event.source_port,
                event.destination_port,
                event.username,
                event.password,
                event.command,
                event.method,
                event.path,
                event.user_agent,
                payload_to_text(event.payload),
                event.attack_type,
                event.risk_score,
                severity,
                psycopg2.extras.Json(raw_log)
            )
        )

        return cur.fetchone()[0]


def should_create_alert(severity: str) -> bool:
    return SEVERITY_RANK.get(severity, 1) >= SEVERITY_RANK.get(ALERT_THRESHOLD, 2)


def upsert_alert(conn, event: HoneypotEvent, severity: str, geo: Dict[str, str]):
    if not should_create_alert(severity):
        return None

    mitre = map_mitre(event.attack_type, event.event_type)
    recommendation = recommendation_for(event, severity)
    title = alert_title(event, severity)
    description = build_description(event, severity, mitre, geo)
    fingerprint = build_fingerprint(event)
    incident_id = "INC-" + fingerprint[:10].upper()

    raw_context = {
        "source_ip": event.source_ip,
        "country": geo.get("country"),
        "city": geo.get("city"),
        "isp": geo.get("isp"),
        "asn": geo.get("asn"),
        "service": event.service,
        "event_type": event.event_type,
        "attack_type": event.attack_type,
        "risk_score": event.risk_score,
        "severity": severity,
        "username": event.username,
        "path": event.path,
        "user_agent": event.user_agent,
        "payload": payload_to_text(event.payload),
        "command": event.command,
    }

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts (
                source_ip, title, severity, risk_score, description, status,
                incident_id, alert_type, service, event_type, attack_type,
                recommendation, mitre_technique, fingerprint, occurrence_count,
                updated_at, raw_context
            )
            VALUES (
                %s, %s, %s, %s, %s, 'open',
                %s, %s, %s, %s, %s,
                %s, %s, %s, 1,
                CURRENT_TIMESTAMP, %s
            )
            ON CONFLICT (fingerprint)
            DO UPDATE SET
                occurrence_count = alerts.occurrence_count + 1,
                risk_score = GREATEST(alerts.risk_score, EXCLUDED.risk_score),
                severity = EXCLUDED.severity,
                description = EXCLUDED.description,
                recommendation = EXCLUDED.recommendation,
                updated_at = CURRENT_TIMESTAMP,
                raw_context = EXCLUDED.raw_context
            RETURNING id, incident_id, occurrence_count;
            """,
            (
                event.source_ip,
                title,
                severity,
                event.risk_score,
                description,
                incident_id,
                event.attack_type or event.event_type,
                event.service,
                event.event_type,
                event.attack_type,
                recommendation,
                mitre,
                fingerprint,
                psycopg2.extras.Json(raw_context)
            )
        )

        return cur.fetchone()


@app.get("/")
def health():
    return {
        "status": "ok",
        "service": "professional-honeypot-soc-api",
        "geoip": "enabled",
        "alert_threshold": ALERT_THRESHOLD
    }


@app.get("/geo/{ip_address}")
def geo_lookup(ip_address: str):
    return {
        "source_ip": ip_address,
        "geo": enrich_ip(ip_address)
    }


@app.post("/events")
def receive_event(event: HoneypotEvent):
    ensure_schema_once()

    geo = normalize_event_before_store(event)
    severity = normalize_severity(event)

    conn = get_conn()

    try:
        update_attacker(conn, event, severity, geo)
        event_db_id = insert_event(conn, event, severity, geo)
        alert_info = upsert_alert(conn, event, severity, geo)
        conn.commit()

        email_result = None

        if alert_info:
            mitre = map_mitre(event.attack_type, event.event_type)
            recommendation = recommendation_for(event, severity)

            occurrence_count = alert_info[2]

            # Prevent email spam:
            # Send email only for first occurrence, Critical alerts,
            # or milestone repeated activity.
            if occurrence_count == 1 or severity == "Critical" or occurrence_count in [5, 10, 20, 50, 100]:
                email_result = send_honeypot_email_alert(
                    event=event,
                    severity=severity,
                    geo=geo,
                    mitre=mitre,
                    recommendation=recommendation,
                    incident_id=alert_info[1],
                    occurrence_count=occurrence_count
                )
            else:
                email_result = {
                    "email_sent": False,
                    "reason": f"Duplicate alert suppressed. occurrence_count={occurrence_count}"
                }

        return {
            "status": "stored",
            "event_id": event_db_id,
            "source_ip": event.source_ip,
            "country": geo.get("country"),
            "city": geo.get("city"),
            "isp": geo.get("isp"),
            "asn": geo.get("asn"),
            "service": event.service,
            "attack_type": event.attack_type,
            "risk_score": event.risk_score,
            "severity": severity,
            "alert_created_or_updated": alert_info is not None,
            "email_notification": email_result,
            "alert": {
                "id": alert_info[0],
                "incident_id": alert_info[1],
                "occurrence_count": alert_info[2],
            } if alert_info else None
        }

    finally:
        conn.close()


@app.get("/stats")
def stats():
    ensure_schema_once()

    conn = get_conn()

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM events;")
            total_events = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM attackers;")
            total_attackers = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM alerts;")
            total_alerts = cur.fetchone()[0]

            cur.execute("SELECT service, COUNT(*) FROM events GROUP BY service ORDER BY COUNT(*) DESC;")
            by_service = cur.fetchall()

            cur.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity ORDER BY COUNT(*) DESC;")
            alerts_by_severity = cur.fetchall()

        return {
            "total_events": total_events,
            "total_attackers": total_attackers,
            "total_alerts": total_alerts,
            "by_service": by_service,
            "alerts_by_severity": alerts_by_severity
        }

    finally:
        conn.close()


@app.get("/events/recent")
def recent_events(limit: int = Query(20, ge=1, le=100)):
    ensure_schema_once()

    conn = get_conn()

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, source_ip, service, event_type, attack_type,
                       username, path, user_agent, risk_score, severity, timestamp,
                       raw_log->'geo' AS geo
                FROM events
                ORDER BY id DESC
                LIMIT %s;
                """,
                (limit,)
            )

            return {"events": cur.fetchall()}

    finally:
        conn.close()


@app.get("/alerts")
def alerts(limit: int = Query(20, ge=1, le=100), status: str = "open"):
    ensure_schema_once()

    conn = get_conn()

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, incident_id, source_ip, title, severity, risk_score,
                       service, event_type, attack_type, mitre_technique,
                       recommendation, occurrence_count, status,
                       raw_context->>'country' AS country,
                       raw_context->>'city' AS city,
                       raw_context->>'isp' AS isp,
                       raw_context->>'asn' AS asn,
                       created_at, updated_at
                FROM alerts
                WHERE status = %s
                ORDER BY
                    CASE severity
                        WHEN 'Critical' THEN 4
                        WHEN 'High' THEN 3
                        WHEN 'Medium' THEN 2
                        ELSE 1
                    END DESC,
                    updated_at DESC
                LIMIT %s;
                """,
                (status, limit)
            )

            return {"alerts": cur.fetchall()}

    finally:
        conn.close()


@app.get("/attackers")
def attackers(limit: int = Query(20, ge=1, le=100)):
    ensure_schema_once()

    conn = get_conn()

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT source_ip, country, city, isp, asn,
                       first_seen, last_seen, total_events,
                       risk_score, severity
                FROM attackers
                ORDER BY risk_score DESC, total_events DESC, last_seen DESC
                LIMIT %s;
                """,
                (limit,)
            )

            return {"attackers": cur.fetchall()}

    finally:
        conn.close()
