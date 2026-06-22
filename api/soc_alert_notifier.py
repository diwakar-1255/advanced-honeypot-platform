import os
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime, timezone

import psycopg2

DB_CONFIG = {
    "dbname": os.getenv("POSTGRES_DB", "honeypotdb"),
    "user": os.getenv("POSTGRES_USER", "honeypot"),
    "password": os.getenv("POSTGRES_PASSWORD"),
    "host": os.getenv("POSTGRES_HOST", "postgres"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
}

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", os.getenv("SMTP_USERNAME", ""))
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", SMTP_USER)
EMAIL_TO = os.getenv("EMAIL_TO", "")

MIN_SEVERITY = os.getenv("SOC_NOTIFY_MIN_SEVERITY", "High")

SEVERITY_ORDER = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

if not DB_CONFIG["password"]:
    raise RuntimeError("POSTGRES_PASSWORD is not set")


def severity_allowed(severity: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(MIN_SEVERITY, 3)


def fetch_unnotified_alerts(cur):
    cur.execute("""
        SELECT id, created_at, rule_name, severity, matched_count, status, description
        FROM soc_alerts
        WHERE notified_at IS NULL
          AND status = 'Open'
        ORDER BY
          CASE severity
            WHEN 'Critical' THEN 4
            WHEN 'High' THEN 3
            WHEN 'Medium' THEN 2
            ELSE 1
          END DESC,
          created_at DESC
        LIMIT 20;
    """)
    rows = cur.fetchall()

    return [
        row for row in rows
        if severity_allowed(row[3])
    ]


def build_message(alerts):
    lines = []
    lines.append("Advanced Honeypot SOC Alert Notification")
    lines.append("=" * 48)
    lines.append(f"Generated UTC: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append(f"New alert count: {len(alerts)}")
    lines.append("")

    for alert in alerts:
        alert_id, created_at, rule_name, severity, matched_count, status, description = alert
        lines.append(f"[{severity}] {rule_name}")
        lines.append(f"Alert ID      : {alert_id}")
        lines.append(f"Created At    : {created_at}")
        lines.append(f"Matched Count : {matched_count}")
        lines.append(f"Status        : {status}")
        lines.append(f"Description   : {description}")
        lines.append("-" * 48)

    return "\n".join(lines)


def send_email(subject, body):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD or not EMAIL_TO:
        print("[*] Email not configured. Printing alert notification only.")
        print(body)
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg.set_content(body)

    context = ssl.create_default_context()

    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=20) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

    print("[+] Email notification sent.")
    return True


def mark_notified(cur, alert_ids):
    cur.execute(
        """
        UPDATE soc_alerts
        SET notified_at = NOW()
        WHERE id = ANY(%s);
        """,
        (alert_ids,),
    )


def main():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            alerts = fetch_unnotified_alerts(cur)

            if not alerts:
                print("[*] No unnotified SOC alerts found.")
                conn.commit()
                return

            body = build_message(alerts)
            subject = f"[HONEYPOT SOC] {len(alerts)} new {MIN_SEVERITY}+ alert(s)"

            send_email(subject, body)

            alert_ids = [row[0] for row in alerts]
            mark_notified(cur, alert_ids)

            conn.commit()
            print(f"[+] Marked {len(alert_ids)} alerts as notified.")

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
