#!/usr/bin/env python3
import os
import ssl
import smtplib
import subprocess
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted, PageBreak
from reportlab.lib.units import inch


ENV_PATH = ".env"
POSTGRES_CONTAINER = "honeypot-postgres"
POSTGRES_USER = "honeypot"
POSTGRES_DB = "honeypotdb"
REPORT_DIR = "daily_soc_reports"


def load_env(path):
    env = {}
    if not os.path.exists(path):
        return env

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def run_sql(sql):
    try:
        result = subprocess.run(
            [
                "docker", "exec", POSTGRES_CONTAINER,
                "psql", "-U", POSTGRES_USER, "-d", POSTGRES_DB,
                "-t", "-A", "-F", " | ",
                "-c", sql
            ],
            capture_output=True,
            text=True,
            timeout=45
        )

        if result.returncode != 0:
            return f"Query failed: {result.stderr.strip()}"

        output = result.stdout.strip()
        return output if output else "No data"
    except Exception as e:
        return f"Error: {e}"


def section(title, content):
    return {
        "title": title,
        "content": content
    }


def collect_report_data():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    sections = []

    sections.append(section("1. Executive Summary", run_sql("""
        SELECT
          COUNT(*) AS total_events,
          COUNT(DISTINCT source_ip) AS unique_attackers,
          COUNT(*) FILTER (WHERE severity IN ('High', 'Critical')) AS high_critical_events,
          COUNT(*) FILTER (WHERE username IS NOT NULL OR password IS NOT NULL) AS captured_credentials,
          COUNT(*) FILTER (WHERE severity = 'Critical') AS critical_events
        FROM events
        WHERE timestamp >= NOW() - INTERVAL '24 hours';
    """)))

    sections.append(section("2. Events by Service", run_sql("""
        SELECT service, COUNT(*) AS events
        FROM events
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY service
        ORDER BY events DESC;
    """)))

    sections.append(section("3. Events by Severity", run_sql("""
        SELECT severity, COUNT(*) AS events
        FROM events
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY severity
        ORDER BY events DESC;
    """)))

    sections.append(section("4. Top Attack Types", run_sql("""
        SELECT attack_type, COUNT(*) AS events
        FROM events
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY attack_type
        ORDER BY events DESC
        LIMIT 10;
    """)))

    sections.append(section("5. Top MITRE ATT&CK Techniques", run_sql("""
        SELECT mitre_id, mitre_tactic, mitre_technique, COUNT(*) AS events
        FROM events
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
          AND mitre_id IS NOT NULL
        GROUP BY mitre_id, mitre_tactic, mitre_technique
        ORDER BY events DESC
        LIMIT 10;
    """)))

    sections.append(section("6. Top Attacker Reputation Profile", run_sql("""
        SELECT
          source_ip,
          country,
          city,
          isp,
          total_events,
          severity,
          COALESCE(reputation_score, 0) AS reputation_score,
          COALESCE(reputation_level, 'Unknown') AS reputation_level
        FROM attackers
        ORDER BY total_events DESC
        LIMIT 15;
    """)))

    sections.append(section("7. Top Correlated Incidents", run_sql("""
        SELECT
          source_ip,
          incident_type,
          severity,
          risk_score,
          event_count,
          services
        FROM incidents
        ORDER BY risk_score DESC, event_count DESC
        LIMIT 15;
    """)))

    sections.append(section("8. SSH Session Replay Summary", run_sql("""
        SELECT
          source_ip,
          username,
          severity,
          risk_score,
          event_count,
          command_count,
          started_at,
          ended_at
        FROM ssh_sessions
        ORDER BY risk_score DESC, event_count DESC
        LIMIT 10;
    """)))

    sections.append(section("9. Latest High/Critical Events", run_sql("""
        SELECT
          timestamp,
          source_ip,
          service,
          attack_type,
          severity,
          mitre_id,
          path
        FROM events
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
          AND severity IN ('High', 'Critical')
        ORDER BY timestamp DESC
        LIMIT 20;
    """)))

    recommendations = """1. Review High and Critical incidents in Grafana.
2. Check top attacker IPs with high reputation scores.
3. Review MITRE techniques with highest frequency.
4. Keep Grafana and PostgreSQL protected from public exposure.
5. Do not publish screenshots containing raw credentials.

Dashboard:
http://52.237.90.251:3000/d/advanced-honeypot-soc?from=now-24h&to=now&refresh=10s
"""
    sections.append(section("10. Recommended Analyst Actions", recommendations))

    return now, sections


def build_text_report(generated_at, sections):
    body = f"""Advanced Honeypot Platform - Daily SOC Report

Generated At: {generated_at}
Scope: Last 24 hours

This report summarizes honeypot activity from Web, HTTPS, SSH, and FTP services.
Raw passwords are intentionally not included in this report.
"""

    for s in sections:
        body += "\n\n" + "=" * 70 + "\n"
        body += s["title"] + "\n"
        body += "=" * 70 + "\n"
        body += s["content"]

    return body


def create_pdf_report(generated_at, sections):
    os.makedirs(REPORT_DIR, exist_ok=True)

    date_name = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    pdf_path = os.path.join(REPORT_DIR, f"honeypot_daily_soc_report_{date_name}.pdf")

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=landscape(A4),
        rightMargin=0.45 * inch,
        leftMargin=0.45 * inch,
        topMargin=0.45 * inch,
        bottomMargin=0.45 * inch
    )

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["BodyText"]

    mono_style = ParagraphStyle(
        "MonoSmall",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7,
        leading=9,
        wordWrap="CJK"
    )

    story = []

    story.append(Paragraph("Advanced Honeypot Platform - Daily SOC Report", title_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<b>Generated At:</b> {generated_at}", normal_style))
    story.append(Paragraph("<b>Scope:</b> Last 24 hours", normal_style))
    story.append(Paragraph(
        "This PDF summarizes honeypot activity from Web, HTTPS, SSH, and FTP services. "
        "Raw passwords are intentionally not included in this report.",
        normal_style
    ))
    story.append(Spacer(1, 12))

    for idx, s in enumerate(sections):
        story.append(Paragraph(s["title"], heading_style))
        safe_content = s["content"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        story.append(Preformatted(safe_content, mono_style))
        story.append(Spacer(1, 10))

        if idx in [3, 6]:
            story.append(PageBreak())

    doc.build(story)
    return pdf_path


def send_email_with_pdf(env, subject, body, pdf_path):
    smtp_host = env.get("SMTP_HOST", "")
    smtp_port = int(env.get("SMTP_PORT", "465"))
    smtp_username = env.get("SMTP_USERNAME", "")
    smtp_password = env.get("SMTP_PASSWORD", "")
    email_from = env.get("EMAIL_FROM", smtp_username)
    email_to = env.get("EMAIL_TO", "")

    if not smtp_host or not smtp_username or not smtp_password or not email_to:
        print("Email configuration missing in .env")
        print("PDF generated at:", pdf_path)
        return False

    recipients = [x.strip() for x in email_to.split(",") if x.strip()]

    msg = MIMEMultipart()
    msg["From"] = email_from
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject

    email_body = """Daily SOC report generated successfully.

The detailed honeypot SOC report is attached as a PDF.

This report includes:
- Executive summary
- Events by service and severity
- Top attack types
- MITRE ATT&CK techniques
- Attacker reputation profile
- Correlated incidents
- SSH session replay summary
- High/Critical events

Raw passwords are intentionally not included in the PDF.
"""
    msg.attach(MIMEText(email_body, "plain"))

    with open(pdf_path, "rb") as f:
        attachment = MIMEApplication(f.read(), _subtype="pdf")

    attachment.add_header(
        "Content-Disposition",
        "attachment",
        filename=os.path.basename(pdf_path)
    )
    msg.attach(attachment)

    use_ssl = env.get("EMAIL_USE_SSL", "true").lower() == "true"

    if use_ssl:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
            server.login(smtp_username, smtp_password)
            server.sendmail(email_from, recipients, msg.as_string())
    else:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(smtp_username, smtp_password)
            server.sendmail(email_from, recipients, msg.as_string())

    return True


def main():
    env = load_env(ENV_PATH)

    generated_at, sections = collect_report_data()
    text_report = build_text_report(generated_at, sections)
    pdf_path = create_pdf_report(generated_at, sections)

    subject_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    subject = f"Daily SOC PDF Report - Advanced Honeypot Platform - {subject_date}"

    sent = send_email_with_pdf(env, subject, text_report, pdf_path)

    if sent:
        print(f"Daily SOC PDF report sent successfully: {pdf_path}")
    else:
        print(f"Daily SOC PDF report generated but email was not sent: {pdf_path}")


if __name__ == "__main__":
    main()
