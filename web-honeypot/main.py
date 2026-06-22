from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from datetime import datetime
import os
import json
import re
import urllib.request
import random

app = FastAPI(
    title="NexaCloud Enterprise Platform",
    docs_url=None,
    redoc_url=None
)

API_URL = os.getenv("CENTRAL_API_URL", "http://api:8000/events")


# -----------------------------
# Request / Detection Helpers
# -----------------------------

def client_ip(request: Request):
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip

    if request.client:
        return request.client.host

    return "unknown"


def service_name(request: Request):
    proto = request.headers.get("x-forwarded-proto", "http")
    return "HTTPS" if proto == "https" else "HTTP"


def dest_port(request: Request):
    proto = request.headers.get("x-forwarded-proto", "http")
    return 443 if proto == "https" else 80


def detect_attack(text: str):
    data = text.lower()

    signatures = {
        "SQL Injection": [
            r"' or '1'='1",
            r"or 1=1",
            r"union select",
            r"information_schema",
            r"sleep\(",
            r"benchmark\(",
            r"drop table",
            r"--",
        ],
        "XSS": [
            r"<script",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"alert\(",
            r"document.cookie",
        ],
        "Path Traversal": [
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"boot.ini",
            r"win.ini",
        ],
        "Command Injection": [
            r";id",
            r";cat",
            r"&&",
            r"\|\|",
            r"wget ",
            r"curl ",
            r"bash -i",
            r"nc ",
            r"python -c",
        ],
        "Scanner": [
            r"sqlmap",
            r"nikto",
            r"nmap",
            r"masscan",
            r"wpscan",
            r"gobuster",
            r"dirbuster",
            r"nessus",
            r"acunetix",
            r"zgrab",
            r"shodan",
        ],
        "Sensitive File Access Attempt": [
            r"\.env",
            r"wp-config",
            r"config.php",
            r"backup",
            r"database.sql",
            r"password",
            r"id_rsa",
            r"\.git",
            r"phpmyadmin",
            r"adminer",
            r"server-status",
        ],
        "Remote Code Execution Attempt": [
            r"phpinfo",
            r"eval\(",
            r"base64_decode",
            r"cmd=",
            r"exec=",
            r"shell",
        ],
    }

    for attack_type, patterns in signatures.items():
        for pattern in patterns:
            if re.search(pattern, data):
                return attack_type

    return "Reconnaissance"


def severity_score(attack_type: str):
    scores = {
        "SQL Injection": ("High", 75),
        "XSS": ("Medium", 55),
        "Path Traversal": ("High", 75),
        "Command Injection": ("Critical", 95),
        "Remote Code Execution Attempt": ("Critical", 95),
        "Scanner": ("Medium", 50),
        "Sensitive File Access Attempt": ("High", 80),
        "Credential Attack": ("Medium", 60),
        "Reconnaissance": ("Low", 25),
    }
    return scores.get(attack_type, ("Low", 20))


def send_event(request: Request, event_type: str, attack_type: str, username=None, password=None, payload=None):
    severity, risk_score = severity_score(attack_type)

    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": client_ip(request),
        "source_port": request.client.port if request.client else None,
        "destination_port": dest_port(request),
        "protocol": "TCP",
        "service": service_name(request),
        "event_type": event_type,
        "username": username,
        "password": password,
        "command": None,
        "url": str(request.url),
        "method": request.method,
        "user_agent": request.headers.get("user-agent", ""),
        "headers": dict(request.headers),
        "payload": payload,
        "attack_type": attack_type,
        "severity": severity,
        "risk_score": risk_score,
    }

    try:
        req = urllib.request.Request(
            API_URL,
            data=json.dumps(event).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception as e:
        print("Failed to send event:", e)


@app.middleware("http")
async def production_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Server"] = "NexaCloud-Edge"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    return response



# BEGIN WEB HONEYTOKEN MIDDLEWARE
WEB_HONEYTOKENS = {
    "/backup/customer_database_backup_2026.sql": {
        "asset": "customer_database_backup_2026.sql",
        "sensitivity": "High",
        "attack_type": "Sensitive File Access Attempt",
        "response": "-- NexaCloud Enterprise Database Backup\n-- Access denied: privileged backup archive.\n"
    },
    "/devops/.env.production": {
        "asset": ".env.production",
        "sensitivity": "Critical",
        "attack_type": "Sensitive File Access Attempt",
        "response": "APP_ENV=production\nDB_HOST=internal-db.nexacloud.local\nDB_USER=readonly_service\nDB_PASSWORD=REDACTED\nJWT_SECRET=REDACTED\n"
    },
    "/cloud/aws_credentials_backup.txt": {
        "asset": "aws_credentials_backup.txt",
        "sensitivity": "Critical",
        "attack_type": "Sensitive File Access Attempt",
        "response": "[production-backup]\naws_access_key_id=REDACTED\naws_secret_access_key=REDACTED\nregion=ap-south-1\n"
    },
    "/admin/password_reset_list.txt": {
        "asset": "password_reset_list.txt",
        "sensitivity": "Critical",
        "attack_type": "Credential Attack",
        "response": "Access denied. This file is restricted to identity administrators.\n"
    },
    "/finance/payment_gateway_keys.txt": {
        "asset": "payment_gateway_keys.txt",
        "sensitivity": "Critical",
        "attack_type": "Sensitive File Access Attempt",
        "response": "Payment gateway key vault access denied. Contact security administrator.\n"
    }
}

@app.middleware("http")
async def web_honeytoken_detector(request: Request, call_next):
    path = request.url.path

    if path in WEB_HONEYTOKENS:
        token = WEB_HONEYTOKENS[path]

        send_event(
            request,
            "Web Honeytoken Access",
            token["attack_type"],
            payload={
                "path": path,
                "asset": token["asset"],
                "sensitivity": token["sensitivity"],
                "query": request.url.query
            }
        )

        return PlainTextResponse(token["response"], status_code=403)

    return await call_next(request)
# END WEB HONEYTOKEN MIDDLEWARE

# -----------------------------
# Realistic Production Layout
# -----------------------------

def layout(title: str, body: str):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title} | NexaCloud Enterprise</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="NexaCloud Enterprise secure cloud, identity, backup and compliance platform.">
<link rel="icon" href="/assets/favicon.ico">
<style>
* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    font-family: Inter, Segoe UI, Arial, sans-serif;
    background: #f4f7fb;
    color: #142033;
}}

.topbar {{
    background: #020617;
    color: #cbd5e1;
    padding: 9px 8%;
    font-size: 13px;
    display: flex;
    justify-content: space-between;
    gap: 15px;
}}

header {{
    background: rgba(15, 23, 42, 0.98);
    color: white;
    padding: 18px 8%;
    position: sticky;
    top: 0;
    z-index: 50;
    box-shadow: 0 8px 25px rgba(0,0,0,0.22);
}}

nav {{
    display: flex;
    justify-content: space-between;
    align-items: center;
}}

.logo {{
    font-size: 25px;
    font-weight: 900;
    letter-spacing: .4px;
}}

.logo span {{
    color: #38bdf8;
}}

nav a {{
    color: #e2e8f0;
    text-decoration: none;
    margin-left: 22px;
    font-size: 14px;
    font-weight: 600;
}}

nav a:hover {{
    color: #38bdf8;
}}

.hero {{
    background:
        radial-gradient(circle at top right, rgba(56,189,248,.35), transparent 32%),
        radial-gradient(circle at bottom left, rgba(34,197,94,.22), transparent 28%),
        linear-gradient(135deg, #0f172a, #1e3a8a 58%, #020617);
    color: white;
    padding: 90px 8%;
}}

.hero-grid {{
    display: grid;
    grid-template-columns: 1.25fr .75fr;
    gap: 42px;
    align-items: center;
}}

.hero h1 {{
    font-size: 54px;
    line-height: 1.08;
    margin: 0 0 20px;
    max-width: 850px;
}}

.hero p {{
    font-size: 18px;
    line-height: 1.75;
    color: #dbeafe;
    max-width: 720px;
}}

.btn {{
    display: inline-block;
    margin-top: 22px;
    margin-right: 12px;
    background: #38bdf8;
    color: #020617;
    padding: 13px 24px;
    border-radius: 10px;
    font-weight: 900;
    text-decoration: none;
}}

.btn-dark {{
    background: #0f172a;
    color: white;
    border: 1px solid #475569;
}}

.security-card {{
    background: rgba(255,255,255,.11);
    border: 1px solid rgba(255,255,255,.22);
    border-radius: 22px;
    padding: 26px;
    backdrop-filter: blur(10px);
}}

.metric {{
    display: flex;
    justify-content: space-between;
    padding: 14px 0;
    border-bottom: 1px solid rgba(255,255,255,.15);
}}

.metric strong {{
    color: #86efac;
}}

.container {{
    padding: 58px 8%;
}}

.section-title {{
    font-size: 34px;
    margin-bottom: 8px;
}}

.muted {{
    color: #64748b;
    line-height: 1.65;
}}

.cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 24px;
    margin-top: 30px;
}}

.card {{
    background: white;
    padding: 26px;
    border-radius: 18px;
    box-shadow: 0 12px 34px rgba(15,23,42,.08);
    border: 1px solid #e2e8f0;
}}

.card h3 {{
    margin-top: 0;
    color: #1d4ed8;
}}

.badge {{
    display: inline-block;
    padding: 6px 10px;
    border-radius: 999px;
    font-size: 12px;
    background: #e0f2fe;
    color: #075985;
    font-weight: 800;
}}

.login-box {{
    max-width: 450px;
    margin: 70px auto;
    background: white;
    padding: 36px;
    border-radius: 20px;
    box-shadow: 0 14px 40px rgba(15,23,42,.15);
}}

input {{
    width: 100%;
    padding: 14px;
    margin: 10px 0;
    border-radius: 11px;
    border: 1px solid #cbd5e1;
    font-size: 15px;
}}

button {{
    width: 100%;
    padding: 14px;
    margin-top: 12px;
    background: #1d4ed8;
    color: white;
    border: none;
    border-radius: 11px;
    font-weight: 900;
    cursor: pointer;
}}

.notice {{
    background: #fff7ed;
    color: #9a3412;
    padding: 14px;
    border-radius: 11px;
    margin-top: 16px;
    font-size: 14px;
}}

.success {{
    background: #ecfdf5;
    color: #047857;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
    border-radius: 16px;
    overflow: hidden;
    box-shadow: 0 12px 34px rgba(15,23,42,.08);
}}

th, td {{
    padding: 15px;
    border-bottom: 1px solid #e2e8f0;
    text-align: left;
}}

th {{
    background: #0f172a;
    color: white;
}}

.status-ok {{
    color: #16a34a;
    font-weight: 900;
}}

.status-warn {{
    color: #f59e0b;
    font-weight: 900;
}}

.status-danger {{
    color: #dc2626;
    font-weight: 900;
}}

pre, code {{
    background: #0f172a;
    color: #dbeafe;
    padding: 12px;
    border-radius: 10px;
    display: block;
    overflow-x: auto;
}}

footer {{
    background: #020617;
    color: #94a3b8;
    padding: 34px 8%;
    font-size: 14px;
}}

@media(max-width: 850px) {{
    .hero-grid {{
        grid-template-columns: 1fr;
    }}

    .hero h1 {{
        font-size: 38px;
    }}

    nav {{
        display: block;
    }}

    nav a {{
        display: inline-block;
        margin: 10px 10px 0 0;
    }}

    .topbar {{
        display: block;
    }}
}}
</style>
</head>

<body>
<div class="topbar">
    <div>Enterprise Cloud Platform | Region: India-South | Build: 2026.06</div>
    <div>Status: Operational | Last sync: {now}</div>
</div>

<header>
    <nav>
        <div class="logo">Nexa<span>Cloud</span></div>
        <div>
            <a href="/">Home</a>
            <a href="/solutions">Solutions</a>
            <a href="/pricing">Pricing</a>
            <a href="/status">Status</a>
            <a href="/docs">Docs</a>
            <a href="/login">Client Login</a>
            <a href="/admin">Admin</a>
        </div>
    </nav>
</header>

{body}

<footer>
    © 2026 NexaCloud Enterprise Systems. Secure cloud, identity, backup and compliance platform.
    <br>Compliance: ISO 27001-ready | SOC monitoring enabled | Audit trail active
</footer>
</body>
</html>
"""


# -----------------------------
# Routes
# -----------------------------

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    send_event(request, "Page Visit", "Reconnaissance")

    body = """
<section class="hero">
    <div class="hero-grid">
        <div>
            <span class="badge">Enterprise Security Platform</span>
            <h1>Secure cloud operations for modern enterprises.</h1>
            <p>
                NexaCloud helps organizations protect identities, monitor access,
                manage encrypted backups, secure APIs and maintain compliance visibility
                across business-critical infrastructure.
            </p>
            <a class="btn" href="/login">Access Client Portal</a>
            <a class="btn btn-dark" href="/solutions">Explore Solutions</a>
        </div>

        <div class="security-card">
            <h3>Live Platform Overview</h3>
            <div class="metric"><span>Client Portal</span><strong>Online</strong></div>
            <div class="metric"><span>API Gateway</span><strong>Online</strong></div>
            <div class="metric"><span>Backup Vault</span><strong>Active</strong></div>
            <div class="metric"><span>Security Monitoring</span><strong>Enabled</strong></div>
            <div class="metric"><span>Audit Logging</span><strong>Enabled</strong></div>
        </div>
    </div>
</section>

<section class="container">
    <h2 class="section-title">Production-grade enterprise services</h2>
    <p class="muted">
        A unified platform for cloud infrastructure, identity protection,
        backup operations and compliance monitoring.
    </p>

    <div class="cards">
        <div class="card">
            <h3>Identity Security</h3>
            <p>Protect privileged users, administrator accounts and client portal access using MFA-ready workflows.</p>
        </div>
        <div class="card">
            <h3>Cloud Backup</h3>
            <p>Encrypted backup vaults, retention policies, recovery workflows and audit-ready reporting.</p>
        </div>
        <div class="card">
            <h3>API Gateway</h3>
            <p>Secure business APIs with token-based authentication, access policies and monitoring.</p>
        </div>
        <div class="card">
            <h3>Compliance Monitoring</h3>
            <p>Centralized event visibility for operations, security reviews and management reporting.</p>
        </div>
    </div>
</section>
"""
    return HTMLResponse(layout("Home", body))


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    send_event(request, "Login Page Visit", "Reconnaissance")

    body = """
<div class="login-box">
    <h2>Client Portal Login</h2>
    <p class="muted">Sign in using your enterprise account.</p>

    <form method="post" action="/login">
        <input name="username" placeholder="Username or email" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit">Sign In</button>
    </form>

    <div class="notice">
        MFA is required for administrator accounts. All authentication attempts are logged.
    </div>
</div>
"""
    return HTMLResponse(layout("Client Login", body))


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    text = f"{username} {password} {str(request.url)} {request.headers.get('user-agent', '')}"
    attack_type = detect_attack(text)

    if attack_type == "Reconnaissance":
        attack_type = "Credential Attack"

    send_event(
        request,
        "Login Attempt",
        attack_type,
        username=username,
        password=password,
        payload={"username": username, "password": password}
    )

    body = """
<div class="login-box">
    <h2>Authentication Failed</h2>
    <p>Invalid username, password or MFA challenge.</p>

    <div class="notice">
        Multiple failed login attempts may temporarily lock the account.
    </div>

    <a class="btn" href="/login">Try Again</a>
</div>
"""
    return HTMLResponse(layout("Login Failed", body), status_code=401)


@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request):
    text = f"/admin {request.headers.get('user-agent', '')}"
    attack_type = detect_attack(text)
    if attack_type == "Reconnaissance":
        attack_type = "Scanner"

    send_event(request, "Admin Console Access Attempt", attack_type)

    body = """
<div class="login-box">
    <h2>Administrator Console</h2>
    <p class="muted">Restricted access for internal administrators only.</p>

    <form method="post" action="/login">
        <input name="username" placeholder="Admin username" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit">Continue</button>
    </form>

    <div class="notice">
        Warning: Administrative access is monitored and protected by MFA.
    </div>
</div>
"""
    return HTMLResponse(layout("Admin Console", body))


@app.get("/solutions", response_class=HTMLResponse)
async def solutions(request: Request):
    send_event(request, "Solutions Page Visit", "Reconnaissance")

    body = """
<section class="container">
    <h2 class="section-title">Solutions</h2>
    <p class="muted">Security-focused infrastructure services for cloud-first organizations.</p>

    <div class="cards">
        <div class="card">
            <h3>Managed Security</h3>
            <p>Continuous monitoring, alerting, audit trails and response workflows.</p>
        </div>
        <div class="card">
            <h3>Compliance Logging</h3>
            <p>Centralized logs for authentication, administrative actions, API usage and backup activity.</p>
        </div>
        <div class="card">
            <h3>Disaster Recovery</h3>
            <p>Encrypted recovery points, backup status, restore validation and service continuity dashboards.</p>
        </div>
        <div class="card">
            <h3>Secure API Operations</h3>
            <p>Token-based API access with rate limiting, gateway monitoring and audit-ready traces.</p>
        </div>
    </div>
</section>
"""
    return HTMLResponse(layout("Solutions", body))


@app.get("/pricing", response_class=HTMLResponse)
async def pricing(request: Request):
    send_event(request, "Pricing Page Visit", "Reconnaissance")

    body = """
<section class="container">
    <h2 class="section-title">Pricing</h2>
    <p class="muted">Flexible plans for startups, enterprises and managed service providers.</p>

    <div class="cards">
        <div class="card">
            <h3>Starter</h3>
            <p>Identity monitoring, dashboard access and basic audit events.</p>
            <h2>₹2,999/month</h2>
        </div>
        <div class="card">
            <h3>Business</h3>
            <p>Backup management, API access, audit logs, alerts and compliance reporting.</p>
            <h2>₹9,999/month</h2>
        </div>
        <div class="card">
            <h3>Enterprise</h3>
            <p>Dedicated support, custom integrations, security operations and advanced monitoring.</p>
            <h2>Contact Sales</h2>
        </div>
    </div>
</section>
"""
    return HTMLResponse(layout("Pricing", body))


@app.get("/status", response_class=HTMLResponse)
async def status(request: Request):
    send_event(request, "Status Page Visit", "Reconnaissance")

    body = f"""
<section class="container">
    <h2 class="section-title">System Status</h2>
    <p class="muted">Live service status for NexaCloud Enterprise platform.</p>

    <table>
        <tr>
            <th>Service</th>
            <th>Status</th>
            <th>Region</th>
            <th>Last Checked</th>
        </tr>
        <tr>
            <td>Client Portal</td>
            <td class="status-ok">Operational</td>
            <td>India-South</td>
            <td>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</td>
        </tr>
        <tr>
            <td>API Gateway</td>
            <td class="status-ok">Operational</td>
            <td>Global</td>
            <td>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</td>
        </tr>
        <tr>
            <td>Backup Storage</td>
            <td class="status-warn">Maintenance Window</td>
            <td>Asia</td>
            <td>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</td>
        </tr>
        <tr>
            <td>Admin Console</td>
            <td class="status-ok">Operational</td>
            <td>Private</td>
            <td>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</td>
        </tr>
    </table>
</section>
"""
    return HTMLResponse(layout("Status", body))


@app.get("/docs", response_class=HTMLResponse)
async def docs(request: Request):
    send_event(request, "Documentation Page Visit", "Reconnaissance")

    body = """
<section class="container">
    <h2 class="section-title">Developer Documentation</h2>
    <p class="muted">API documentation for enterprise integrations.</p>

    <div class="cards">
        <div class="card">
            <h3>Authentication</h3>
            <p>Use API tokens and signed requests for secure access.</p>
            <code>POST /api/v1/auth/token</code>
        </div>
        <div class="card">
            <h3>User API</h3>
            <p>Manage users, roles and access policies.</p>
            <code>GET /api/v1/users</code>
        </div>
        <div class="card">
            <h3>Backup API</h3>
            <p>View backup status and restoration events.</p>
            <code>GET /api/v1/backups</code>
        </div>
        <div class="card">
            <h3>Audit API</h3>
            <p>Query administrative actions and compliance audit history.</p>
            <code>GET /api/v1/audit/events</code>
        </div>
    </div>
</section>
"""
    return HTMLResponse(layout("Docs", body))


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots(request: Request):
    send_event(request, "Robots File Access", "Reconnaissance")
    return """User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /api/v1/internal
Disallow: /config
Disallow: /.env
Disallow: /.git
Disallow: /database
"""


@app.get("/sitemap.xml", response_class=PlainTextResponse)
async def sitemap(request: Request):
    send_event(request, "Sitemap Access", "Reconnaissance")
    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset>
  <url><loc>https://nexacloud.local/</loc></url>
  <url><loc>https://nexacloud.local/login</loc></url>
  <url><loc>https://nexacloud.local/solutions</loc></url>
  <url><loc>https://nexacloud.local/pricing</loc></url>
  <url><loc>https://nexacloud.local/status</loc></url>
  <url><loc>https://nexacloud.local/docs</loc></url>
</urlset>
"""


@app.get("/.well-known/security.txt", response_class=PlainTextResponse)
async def security_txt(request: Request):
    send_event(request, "Security TXT Access", "Reconnaissance")
    return """Contact: security@nexacloud.local
Policy: https://nexacloud.local/security-policy
Preferred-Languages: en
Expires: 2026-12-31T23:59:59Z
"""


@app.get("/api/v1/health")
async def api_health(request: Request):
    send_event(request, "API Health Endpoint Access", "Reconnaissance")
    return JSONResponse({
        "status": "ok",
        "region": "india-south",
        "service": "nexacloud-api-gateway",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })


@app.post("/api/v1/auth/token")
async def api_token(request: Request):
    body = await request.body()
    text = body.decode(errors="ignore")
    attack_type = detect_attack(text)
    if attack_type == "Reconnaissance":
        attack_type = "Credential Attack"

    send_event(
        request,
        "API Token Request",
        attack_type,
        payload={"body": text[:500]}
    )

    return JSONResponse(
        {
            "error": "invalid_client",
            "message": "Client authentication failed",
            "status": 401,
        },
        status_code=401,
    )


@app.get("/api/v1/users")
async def api_users(request: Request):
    send_event(request, "API Users Endpoint Access", "Reconnaissance")
    return JSONResponse(
        {
            "error": "Unauthorized",
            "message": "Valid bearer token required",
            "status": 401,
        },
        status_code=401,
    )


@app.get("/api/v1/backups")
async def api_backups(request: Request):
    send_event(request, "API Backups Endpoint Access", "Reconnaissance")
    return JSONResponse(
        {
            "error": "Forbidden",
            "message": "Insufficient permissions for backup inventory",
            "status": 403,
        },
        status_code=403,
    )


@app.get("/api/v1/audit/events")
async def api_audit_events(request: Request):
    send_event(request, "Audit API Access Attempt", "Reconnaissance")
    return JSONResponse(
        {
            "error": "Forbidden",
            "message": "Audit API requires administrative privileges",
            "status": 403,
        },
        status_code=403,
    )


@app.get("/assets/app.js", response_class=PlainTextResponse)
async def app_js(request: Request):
    send_event(request, "Static JS Access", "Reconnaissance")
    return """console.log("NexaCloud Enterprise Portal loaded");"""


@app.get("/assets/main.css", response_class=PlainTextResponse)
async def main_css(request: Request):
    send_event(request, "Static CSS Access", "Reconnaissance")
    return """/* NexaCloud Enterprise production stylesheet */"""


@app.get("/{path:path}", response_class=HTMLResponse)
async def catch_all(request: Request, path: str):
    full_path = "/" + path
    text = f"{full_path} {request.url.query} {request.headers.get('user-agent', '')}"
    attack_type = detect_attack(text)

    web_honeytokens = {
        "/backup/customer_database_backup_2026.sql": {
            "asset": "customer_database_backup_2026.sql",
            "sensitivity": "High",
            "attack_type": "Sensitive File Access Attempt",
            "response": "-- NexaCloud Enterprise Database Backup\\n-- Access denied: privileged backup archive.\\n"
        },
        "/devops/.env.production": {
            "asset": ".env.production",
            "sensitivity": "Critical",
            "attack_type": "Sensitive File Access Attempt",
            "response": "APP_ENV=production\\nDB_HOST=internal-db.nexacloud.local\\nDB_USER=readonly_service\\nDB_PASSWORD=REDACTED\\nJWT_SECRET=REDACTED\\n"
        },
        "/cloud/aws_credentials_backup.txt": {
            "asset": "aws_credentials_backup.txt",
            "sensitivity": "Critical",
            "attack_type": "Sensitive File Access Attempt",
            "response": "[production-backup]\\naws_access_key_id=REDACTED\\naws_secret_access_key=REDACTED\\nregion=ap-south-1\\n"
        },
        "/admin/password_reset_list.txt": {
            "asset": "password_reset_list.txt",
            "sensitivity": "Critical",
            "attack_type": "Credential Attack",
            "response": "Access denied. This file is restricted to identity administrators.\\n"
        },
        "/finance/payment_gateway_keys.txt": {
            "asset": "payment_gateway_keys.txt",
            "sensitivity": "Critical",
            "attack_type": "Sensitive File Access Attempt",
            "response": "Payment gateway key vault access denied. Contact security administrator.\\n"
        }
    }

    if full_path in web_honeytokens:
        token = web_honeytokens[full_path]
        send_event(
            request,
            "Web Honeytoken Access",
            token["attack_type"],
            payload={
                "path": full_path,
                "asset": token["asset"],
                "sensitivity": token["sensitivity"],
                "query": request.url.query
            }
        )
        return PlainTextResponse(token["response"], status_code=403)

    send_event(
        request,
        "Suspicious Web Request",
        attack_type,
        payload={"path": full_path, "query": request.url.query}
    )

    sensitive = [
        ".env",
        ".git",
        "wp-config",
        "config",
        "backup",
        "database",
        "password",
        "id_rsa",
        "phpmyadmin",
        "server-status",
        "adminer",
        "debug",
        "actuator",
    ]

    if any(item in full_path.lower() for item in sensitive):
        body = """
<div class="login-box">
    <h2>403 Forbidden</h2>
    <p>You do not have permission to access this resource.</p>
    <div class="notice">This access attempt has been logged.</div>
</div>
"""
        return HTMLResponse(layout("403 Forbidden", body), status_code=403)

    body = """
<div class="login-box">
    <h2>404 Not Found</h2>
    <p>The requested resource could not be found on this server.</p>
</div>
"""
    return HTMLResponse(layout("404 Not Found", body), status_code=404)

@app.get("/backup/customer_database_backup_2026.sql", response_class=PlainTextResponse)
async def fake_customer_backup(request: Request):
    send_event(
        request,
        "Web Honeytoken Access",
        "Sensitive File Access Attempt",
        payload={"asset": "customer_database_backup_2026.sql", "sensitivity": "High"}
    )
    return """-- NexaCloud Enterprise Database Backup
-- Export Date: 2026-06-22
-- Access denied: backup archive requires privileged credentials.
"""

@app.get("/devops/.env.production", response_class=PlainTextResponse)
async def fake_env_production(request: Request):
    send_event(
        request,
        "Web Honeytoken Access",
        "Sensitive File Access Attempt",
        payload={"asset": ".env.production", "sensitivity": "Critical"}
    )
    return """APP_ENV=production
DB_HOST=internal-db.nexacloud.local
DB_USER=readonly_service
DB_PASSWORD=REDACTED
JWT_SECRET=REDACTED
"""

@app.get("/cloud/aws_credentials_backup.txt", response_class=PlainTextResponse)
async def fake_aws_credentials(request: Request):
    send_event(
        request,
        "Web Honeytoken Access",
        "Sensitive File Access Attempt",
        payload={"asset": "aws_credentials_backup.txt", "sensitivity": "Critical"}
    )
    return """[production-backup]
aws_access_key_id=REDACTED
aws_secret_access_key=REDACTED
region=ap-south-1
"""

@app.get("/admin/password_reset_list.txt", response_class=PlainTextResponse)
async def fake_password_reset_list(request: Request):
    send_event(
        request,
        "Web Honeytoken Access",
        "Credential Attack",
        payload={"asset": "password_reset_list.txt", "sensitivity": "Critical"}
    )
    return """Access denied.
This file is restricted to identity administrators.
"""

@app.get("/finance/payment_gateway_keys.txt", response_class=PlainTextResponse)
async def fake_payment_keys(request: Request):
    send_event(
        request,
        "Web Honeytoken Access",
        "Sensitive File Access Attempt",
        payload={"asset": "payment_gateway_keys.txt", "sensitivity": "Critical"}
    )
    return """Payment gateway key vault access denied.
Contact security administrator.
"""
