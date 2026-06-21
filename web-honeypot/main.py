from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from datetime import datetime
import os
import json
import re
import urllib.request

app = FastAPI(title="Advanced Enterprise HTTPS Honeypot")

API_URL = os.getenv("CENTRAL_API_URL", "http://api:8000/events")


# -----------------------------
# Utility functions
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
    return 8443 if proto == "https" else 8080


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
        ],
    }

    for attack_type, patterns in signatures.items():
        for pattern in patterns:
            if re.search(pattern, data):
                return attack_type

    return "Reconnaissance"


def severity_score(attack_type: str):
    scores = {
        "SQL Injection": ("High", 70),
        "XSS": ("Medium", 55),
        "Path Traversal": ("High", 75),
        "Command Injection": ("Critical", 90),
        "Scanner": ("Medium", 45),
        "Sensitive File Access Attempt": ("High", 70),
        "Credential Attack": ("Medium", 50),
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


# -----------------------------
# Website design
# -----------------------------

def layout(title: str, body: str):
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title} | NexaCloud Enterprise</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
* {{
    box-sizing: border-box;
    font-family: Inter, Arial, Helvetica, sans-serif;
}}

body {{
    margin: 0;
    background: #f5f7fb;
    color: #172033;
}}

.topbar {{
    background: #020617;
    color: #cbd5e1;
    padding: 8px 8%;
    font-size: 13px;
    display: flex;
    justify-content: space-between;
}}

header {{
    background: rgba(15, 23, 42, 0.98);
    color: white;
    padding: 18px 8%;
    position: sticky;
    top: 0;
    z-index: 10;
    box-shadow: 0 5px 20px rgba(0,0,0,0.25);
}}

nav {{
    display: flex;
    justify-content: space-between;
    align-items: center;
}}

.logo {{
    font-size: 24px;
    font-weight: 800;
    letter-spacing: 0.5px;
}}

.logo span {{
    color: #38bdf8;
}}

nav a {{
    color: #e2e8f0;
    text-decoration: none;
    margin-left: 24px;
    font-size: 14px;
}}

nav a:hover {{
    color: #38bdf8;
}}

.hero {{
    background:
        radial-gradient(circle at top right, rgba(56,189,248,0.35), transparent 30%),
        linear-gradient(135deg, #0f172a, #1e3a8a 60%, #020617);
    color: white;
    padding: 90px 8%;
}}

.hero-grid {{
    display: grid;
    grid-template-columns: 1.3fr 0.7fr;
    gap: 40px;
    align-items: center;
}}

.hero h1 {{
    font-size: 52px;
    line-height: 1.1;
    max-width: 780px;
    margin: 0 0 20px;
}}

.hero p {{
    font-size: 18px;
    line-height: 1.7;
    color: #dbeafe;
    max-width: 680px;
}}

.btn {{
    display: inline-block;
    margin-top: 24px;
    background: #38bdf8;
    color: #020617;
    padding: 13px 24px;
    border-radius: 10px;
    font-weight: 800;
    text-decoration: none;
}}

.btn-dark {{
    background: #0f172a;
    color: white;
}}

.security-card {{
    background: rgba(255,255,255,0.10);
    border: 1px solid rgba(255,255,255,0.20);
    border-radius: 20px;
    padding: 24px;
    backdrop-filter: blur(8px);
}}

.metric {{
    display: flex;
    justify-content: space-between;
    padding: 14px 0;
    border-bottom: 1px solid rgba(255,255,255,0.15);
}}

.container {{
    padding: 55px 8%;
}}

.section-title {{
    font-size: 32px;
    margin-bottom: 10px;
}}

.muted {{
    color: #64748b;
    line-height: 1.6;
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
    box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08);
    border: 1px solid #e2e8f0;
}}

.card h3 {{
    color: #1d4ed8;
    margin-top: 0;
}}

.login-box {{
    max-width: 420px;
    margin: 70px auto;
    background: white;
    padding: 34px;
    border-radius: 18px;
    box-shadow: 0 10px 35px rgba(15, 23, 42, 0.15);
}}

.login-box h2 {{
    margin-top: 0;
}}

input {{
    width: 100%;
    padding: 13px;
    margin: 10px 0;
    border-radius: 10px;
    border: 1px solid #cbd5e1;
}}

button {{
    width: 100%;
    padding: 13px;
    margin-top: 12px;
    background: #1d4ed8;
    color: white;
    border: none;
    border-radius: 10px;
    font-weight: bold;
    cursor: pointer;
}}

.notice {{
    background: #fff7ed;
    color: #9a3412;
    padding: 14px;
    border-radius: 10px;
    margin-top: 15px;
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
    box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08);
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
    font-weight: bold;
}}

.status-warn {{
    color: #f59e0b;
    font-weight: bold;
}}

.status-danger {{
    color: #dc2626;
    font-weight: bold;
}}

footer {{
    background: #020617;
    color: #94a3b8;
    padding: 30px 8%;
    font-size: 14px;
}}

@media(max-width: 800px) {{
    .hero-grid {{
        grid-template-columns: 1fr;
    }}

    .hero h1 {{
        font-size: 36px;
    }}

    nav {{
        display: block;
    }}

    nav a {{
        display: inline-block;
        margin: 10px 10px 0 0;
    }}
}}
</style>
</head>

<body>

<div class="topbar">
    <div>Enterprise Security Platform | Region: India-South</div>
    <div>Status: Operational | Support: 24/7</div>
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
            <h1>Secure Cloud Infrastructure for Enterprise Operations</h1>
            <p>
                NexaCloud helps organizations protect identities, monitor access,
                manage cloud backups, and secure business-critical APIs through
                a unified enterprise platform.
            </p>
            <a class="btn" href="/login">Access Client Portal</a>
            <a class="btn btn-dark" href="/solutions">View Solutions</a>
        </div>

        <div class="security-card">
            <h3>Live Platform Overview</h3>
            <div class="metric"><span>Client Portal</span><strong>Online</strong></div>
            <div class="metric"><span>API Gateway</span><strong>Online</strong></div>
            <div class="metric"><span>Backup Region</span><strong>Active</strong></div>
            <div class="metric"><span>Security Monitoring</span><strong>Enabled</strong></div>
        </div>
    </div>
</section>

<section class="container">
    <h2 class="section-title">Enterprise Services</h2>
    <p class="muted">A secure platform built for cloud operations, identity management, backups and compliance monitoring.</p>

    <div class="cards">
        <div class="card">
            <h3>Identity Security</h3>
            <p>Protect privileged users, administrator accounts and client portal access.</p>
        </div>
        <div class="card">
            <h3>Cloud Backup</h3>
            <p>Encrypted backup vaults, retention policies and recovery workflows.</p>
        </div>
        <div class="card">
            <h3>API Gateway</h3>
            <p>Secure business APIs with access control, keys and audit logging.</p>
        </div>
        <div class="card">
            <h3>Threat Monitoring</h3>
            <p>Real-time visibility into suspicious access and abnormal login behavior.</p>
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
        MFA is required for administrator accounts. All access attempts are logged.
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


@app.get("/solutions", response_class=HTMLResponse)
async def solutions(request: Request):
    send_event(request, "Solutions Page Visit", "Reconnaissance")

    body = """
<section class="container">
    <h2 class="section-title">Solutions</h2>
    <p class="muted">Security-focused infrastructure for cloud-first organizations.</p>

    <div class="cards">
        <div class="card">
            <h3>Managed Security</h3>
            <p>Continuous monitoring, alerting, audit trails and response workflows.</p>
        </div>
        <div class="card">
            <h3>Compliance Logging</h3>
            <p>Centralized logs for authentication, administrative actions and API usage.</p>
        </div>
        <div class="card">
            <h3>Disaster Recovery</h3>
            <p>Encrypted recovery points, backup status and restoration verification.</p>
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
            <p>Identity monitoring and basic dashboard access.</p>
            <h2>₹2,999/month</h2>
        </div>
        <div class="card">
            <h3>Business</h3>
            <p>Backup management, API access, audit logs and alerts.</p>
            <h2>₹9,999/month</h2>
        </div>
        <div class="card">
            <h3>Enterprise</h3>
            <p>Dedicated support, custom integrations and advanced monitoring.</p>
            <h2>Contact Sales</h2>
        </div>
    </div>
</section>
"""
    return HTMLResponse(layout("Pricing", body))


@app.get("/status", response_class=HTMLResponse)
async def status(request: Request):
    send_event(request, "Status Page Visit", "Reconnaissance")

    body = """
<section class="container">
    <h2 class="section-title">System Status</h2>
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
            <td>Just now</td>
        </tr>
        <tr>
            <td>API Gateway</td>
            <td class="status-ok">Operational</td>
            <td>Global</td>
            <td>Just now</td>
        </tr>
        <tr>
            <td>Backup Storage</td>
            <td class="status-warn">Maintenance Window</td>
            <td>Asia</td>
            <td>10 minutes ago</td>
        </tr>
        <tr>
            <td>Admin Console</td>
            <td class="status-ok">Operational</td>
            <td>Private</td>
            <td>Just now</td>
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
    </div>
</section>
"""
    return HTMLResponse(layout("Docs", body))


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
"""


@app.get("/sitemap.xml", response_class=PlainTextResponse)
async def sitemap(request: Request):
    send_event(request, "Sitemap Access", "Reconnaissance")

    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset>
  <url><loc>https://localhost/</loc></url>
  <url><loc>https://localhost/login</loc></url>
  <url><loc>https://localhost/solutions</loc></url>
  <url><loc>https://localhost/status</loc></url>
</urlset>
"""


@app.get("/.well-known/security.txt", response_class=PlainTextResponse)
async def security_txt(request: Request):
    send_event(request, "Security TXT Access", "Reconnaissance")

    return """Contact: security@nexacloud.local
Policy: https://localhost/security-policy
Preferred-Languages: en
"""


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


@app.get("/{path:path}", response_class=HTMLResponse)
async def catch_all(request: Request, path: str):
    full_path = "/" + path
    text = f"{full_path} {request.url.query} {request.headers.get('user-agent', '')}"
    attack_type = detect_attack(text)

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
