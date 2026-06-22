import os
import psycopg2
from datetime import datetime, timezone

DB_CONFIG = {
    "dbname": os.getenv("POSTGRES_DB", "honeypotdb"),
    "user": os.getenv("POSTGRES_USER", "honeypot"),
    "password": os.getenv("POSTGRES_PASSWORD"),
    "host": os.getenv("POSTGRES_HOST", "postgres"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
}

if not DB_CONFIG["password"]:
    raise RuntimeError("POSTGRES_PASSWORD is not set")

RULES = [
    {
        "name": "Critical Web Honeytoken Access",
        "severity": "Critical",
        "description": "A high-value web honeytoken/deception file was accessed.",
        "sql": """
            SELECT COUNT(*)
            FROM events
            WHERE event_type = 'Web Honeytoken Access'
              AND timestamp >= NOW() - INTERVAL '30 minutes';
        """,
        "threshold": 0,
    },
    {
        "name": "Repeated SSH Credential Attacks",
        "severity": "High",
        "description": "Multiple SSH credential attempts detected.",
        "sql": """
            SELECT COUNT(*)
            FROM events
            WHERE service = 'SSH'
              AND (username IS NOT NULL OR password IS NOT NULL)
              AND timestamp >= NOW() - INTERVAL '30 minutes';
        """,
        "threshold": 10,
    },
    {
        "name": "High Risk Attacker Activity",
        "severity": "High",
        "description": "High or critical severity activity detected.",
        "sql": """
            SELECT COUNT(*)
            FROM events
            WHERE severity IN ('High', 'Critical')
              AND timestamp >= NOW() - INTERVAL '30 minutes';
        """,
        "threshold": 20,
    },
    {
        "name": "Web Scanner Flood Detected",
        "severity": "Medium",
        "description": "Rate-limited web scanner activity detected.",
        "sql": """
            SELECT COUNT(*)
            FROM events
            WHERE event_type = 'Web Rate Limited'
              AND timestamp >= NOW() - INTERVAL '30 minutes';
        """,
        "threshold": 0,
    },
    {
        "name": "Multi-Service Attacker Detected",
        "severity": "High",
        "description": "Same IP interacted with 3 or more honeypot services.",
        "sql": """
            SELECT COUNT(*)
            FROM (
                SELECT source_ip
                FROM events
                WHERE timestamp >= NOW() - INTERVAL '60 minutes'
                GROUP BY source_ip
                HAVING COUNT(DISTINCT service) >= 3
            ) x;
        """,
        "threshold": 0,
    },
]

def ensure_alert_table(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS soc_alerts (
            id SERIAL PRIMARY KEY,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            matched_count INTEGER NOT NULL,
            status TEXT DEFAULT 'Open',
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_soc_alerts_created_at
        ON soc_alerts(created_at);
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_soc_alerts_rule_status
        ON soc_alerts(rule_name, status);
    """)

def recent_alert_exists(cur, rule_name):
    cur.execute(
        """
        SELECT COUNT(*)
        FROM soc_alerts
        WHERE rule_name = %s
          AND created_at >= NOW() - INTERVAL '30 minutes';
        """,
        (rule_name,),
    )
    return cur.fetchone()[0] > 0

def main():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            ensure_alert_table(cur)

            created = 0

            for rule in RULES:
                cur.execute(rule["sql"])
                count = int(cur.fetchone()[0])

                if count > rule["threshold"]:
                    if recent_alert_exists(cur, rule["name"]):
                        print(f"[*] Recent alert already exists: {rule['name']} count={count}")
                        continue

                    cur.execute(
                        """
                        INSERT INTO soc_alerts
                        (rule_name, severity, description, matched_count, status, created_at)
                        VALUES (%s, %s, %s, %s, 'Open', NOW());
                        """,
                        (
                            rule["name"],
                            rule["severity"],
                            rule["description"],
                            count,
                        ),
                    )

                    print(f"[+] Alert created: {rule['name']} count={count}")
                    created += 1
                else:
                    print(f"[-] No alert: {rule['name']} count={count}")

            conn.commit()
            print(f"[+] SOC alert engine completed at {datetime.now(timezone.utc).isoformat()}")
            print(f"[+] New alerts created: {created}")

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    main()
