import os
import ssl
import smtplib
from email.message import EmailMessage
from typing import Dict, Any


SEVERITY_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}


def env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() == "true"


EMAIL_ENABLED = env_bool("EMAIL_ENABLED", "false")
ALERT_NOTIFY_MIN_SEVERITY = os.getenv("ALERT_NOTIFY_MIN_SEVERITY", "High")

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", SMTP_USERNAME)
EMAIL_TO = os.getenv("EMAIL_TO", "")
EMAIL_USE_SSL = env_bool("EMAIL_USE_SSL", "true")
EMAIL_USE_TLS = env_bool("EMAIL_USE_TLS", "false")


def severity_allowed(severity: str) -> bool:
    current = SEVERITY_RANK.get(severity, 1)
    required = SEVERITY_RANK.get(ALERT_NOTIFY_MIN_SEVERITY, 3)
    return current >= required


def payload_to_text(payload: Any) -> str:
    if payload is None:
        return ""
    return str(payload)


def build_email_message(
    event,
    severity: str,
    geo: Dict[str, str],
    mitre: str,
    recommendation: str,
    incident_id: str,
    occurrence_count: int
) -> str:
    lines = [
        "HONEYPOT SOC EMAIL ALERT",
        "",
        f"Incident ID: {incident_id}",
        f"Severity: {severity}",
        f"Risk Score: {event.risk_score}",
        f"Occurrence Count: {occurrence_count}",
        "",
        "ATTACKER DETAILS",
        f"Source IP: {event.source_ip}",
        f"Country: {geo.get('country', 'Unknown')}",
        f"City: {geo.get('city', 'Unknown')}",
        f"ISP: {geo.get('isp', 'Unknown')}",
        f"ASN: {geo.get('asn', 'Unknown')}",
        "",
        "EVENT DETAILS",
        f"Service: {event.service}",
        f"Event Type: {event.event_type}",
        f"Attack Type: {event.attack_type or 'Unknown'}",
        f"MITRE Technique: {mitre}",
    ]

    if event.username:
        lines.append(f"Username: {event.username}")

    if event.password:
        lines.append("Password Captured: ****")

    if event.path:
        lines.append(f"Path: {event.path}")

    if event.user_agent:
        lines.append(f"User-Agent: {event.user_agent}")

    if event.payload:
        lines.append(f"Payload: {payload_to_text(event.payload)[:500]}")

    lines.extend([
        "",
        "RECOMMENDATION",
        recommendation,
        "",
        "Grafana Dashboard",
        "http://localhost:3000/d/advanced-honeypot-soc"
    ])

    return "\n".join(lines)


def send_email(subject: str, body: str) -> bool:
    if not EMAIL_ENABLED:
        print("Email alert skipped: EMAIL_ENABLED=false")
        return False

    if not SMTP_HOST or not SMTP_USERNAME or not SMTP_PASSWORD or not EMAIL_TO:
        print("Email alert skipped: SMTP configuration missing")
        return False

    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        msg.set_content(body)

        context = ssl.create_default_context()

        if EMAIL_USE_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as server:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
                server.ehlo()
                if EMAIL_USE_TLS:
                    server.starttls(context=context)
                    server.ehlo()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)

        print("Email alert sent successfully.")
        return True

    except Exception as exc:
        print("Email alert failed:", exc)
        return False


def send_honeypot_email_alert(
    event,
    severity: str,
    geo: Dict[str, str],
    mitre: str,
    recommendation: str,
    incident_id: str,
    occurrence_count: int
) -> Dict[str, Any]:
    if not severity_allowed(severity):
        return {
            "email_sent": False,
            "reason": f"Severity {severity} below threshold {ALERT_NOTIFY_MIN_SEVERITY}"
        }

    subject = f"[HONEYPOT {severity}] {incident_id} - {event.attack_type or event.event_type}"

    body = build_email_message(
        event=event,
        severity=severity,
        geo=geo,
        mitre=mitre,
        recommendation=recommendation,
        incident_id=incident_id,
        occurrence_count=occurrence_count
    )

    sent = send_email(subject, body)

    return {
        "email_sent": sent
    }
