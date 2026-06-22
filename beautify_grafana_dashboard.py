import os
import json
import base64
import urllib.request
import urllib.error
from datetime import datetime

GRAFANA_URL = "http://localhost:3000"
DASHBOARD_UID = "advanced-honeypot-soc"
ADMIN_USER = "admin"
ADMIN_PASS = os.getenv("GRAFANA_ADMIN_PASSWORD", "")

if not ADMIN_PASS:
    raise SystemExit("GRAFANA_ADMIN_PASSWORD is not set")

auth = base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASS}".encode()).decode()

def api(method, path, data=None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        GRAFANA_URL + path,
        data=body,
        method=method,
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            raw = res.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        raise SystemExit(f"HTTP {e.code} {path}: {raw}")

def row_panel(title, y):
    return {
        "id": abs(hash(title)) % 1000000,
        "type": "row",
        "title": title,
        "collapsed": False,
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
        "panels": [],
    }

def get_panel(title, panels):
    for p in panels:
        if p.get("title") == title:
            return p
    return None

def set_grid(panel, x, y, w, h):
    panel["gridPos"] = {"x": x, "y": y, "w": w, "h": h}
    return panel

resp = api("GET", f"/api/dashboards/uid/{DASHBOARD_UID}")
dashboard = resp["dashboard"]
meta = resp.get("meta", {})

original_panels = dashboard.get("panels", [])

# Backup dashboard JSON locally
backup_name = f"grafana_dashboard_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(backup_name, "w") as f:
    json.dump(dashboard, f, indent=2)
print(f"[+] Backup saved: {backup_name}")

# Remove old row panels only; keep all real panels
real_panels = [
    p for p in original_panels
    if p.get("type") != "row"
]

used_titles = set()
new_panels = []
y = 0

def add_section(title, items):
    global y
    new_panels.append(row_panel(title, y))
    y += 1

    for panel_title, x, w, h in items:
        panel = get_panel(panel_title, real_panels)
        if not panel:
            print(f"[*] Missing panel, skipped: {panel_title}")
            continue

        used_titles.add(panel_title)
        new_panels.append(set_grid(panel, x, y, w, h))

    if items:
        y += max(h for _, _, _, h in items)

# 1. Executive Overview
add_section("01 - Executive Overview", [
    ("Total Events", 0, 6, 4),
    ("Unique Attackers", 6, 6, 4),
    ("High Risk Events", 12, 6, 4),
    ("Captured Credentials", 18, 6, 4),
])

# 2. World Map and Geo
add_section("02 - World Map & Geo Intelligence", [
    ("World Attack Map", 0, 12, 9),
    ("Events by Country", 12, 6, 9),
    ("Events by City", 18, 6, 9),
])

add_section("03 - Attacker Geo Profile", [
    ("Attacker Geo Profile", 0, 24, 10),
])

# 3. Attack Analysis
add_section("04 - Attack Analysis", [
    ("Events by Service", 0, 8, 8),
    ("Top Attack Types", 8, 8, 8),
    ("Events by Severity", 16, 8, 8),
])

add_section("05 - Recent Events & Credentials", [
    ("Recent Honeypot Events", 0, 16, 10),
    ("Captured Credentials Table", 16, 8, 10),
])

# 4. MITRE
add_section("06 - MITRE ATT&CK Mapping", [
    ("Top MITRE Techniques", 0, 8, 9),
    ("MITRE Tactics by Severity", 8, 8, 9),
    ("High/Critical MITRE Events", 16, 8, 9),
])

add_section("07 - MITRE by Attacker", [
    ("MITRE by Attacker IP", 0, 24, 10),
])

# 5. Incidents
add_section("08 - Incident Response Overview", [
    ("Open Incidents", 0, 6, 4),
    ("High/Critical Incidents", 6, 6, 4),
    ("Max Incident Risk", 12, 6, 4),
    ("Multi-Service Campaigns", 18, 6, 4),
])

add_section("09 - Incident Campaigns", [
    ("Incident Campaigns", 0, 12, 11),
    ("Critical/High Incident Summary", 12, 12, 11),
])

# 6. Reputation
add_section("10 - Threat Reputation", [
    ("Critical Reputation IPs", 0, 6, 4),
    ("High Reputation IPs", 6, 6, 4),
    ("Cloud/Hosting Attackers", 12, 6, 4),
    ("Max Reputation Score", 18, 6, 4),
])

add_section("11 - Threat Reputation Profile", [
    ("Threat Reputation Profile", 0, 24, 10),
])

# 7. SSH
add_section("12 - SSH Session Analysis", [
    ("SSH Sessions", 0, 6, 4),
    ("High SSH Sessions", 6, 6, 4),
    ("SSH Command Sessions", 12, 6, 4),
    ("Max SSH Session Risk", 18, 6, 4),
])

add_section("13 - SSH Session Replay", [
    ("SSH Session Replay", 0, 24, 10),
])

# 8. Malware
add_section("14 - Malware / Uploaded File Analysis", [
    ("Uploaded Samples", 0, 6, 4),
    ("YARA Matched Samples", 6, 6, 4),
    ("Suspicious Samples", 12, 6, 4),
    ("Max Sample Risk", 18, 6, 4),
])

add_section("15 - Malware Details", [
    ("Malware / Uploaded File Analysis", 0, 24, 9),
])

# 9. Deception
add_section("16 - Deception Asset Overview", [
    ("Deception Assets", 0, 6, 4),
    ("Critical Honeytokens", 6, 6, 4),
    ("Honeytoken Accesses", 12, 6, 4),
    ("Critical Honeytoken Accesses", 18, 6, 4),
])

add_section("17 - Deception Asset Inventory", [
    ("Deception Asset Inventory", 0, 24, 10),
])

add_section("18 - Honeytoken Access Analysis", [
    ("Honeytoken Access Timeline", 0, 12, 10),
    ("Top Honeytoken Attackers", 12, 12, 10),
])

# 10. Web Honeytokens
add_section("19 - Web Honeytoken Detection", [
    ("Web Honeytoken Accesses", 0, 6, 4),
    ("Top Web Honeytoken Paths", 6, 9, 8),
    ("Web Honeytoken Timeline", 15, 9, 8),
])

# 11. SOC Alerts
add_section("20 - SOC Alerts", [
    ("Open SOC Alerts", 0, 6, 4),
    ("Critical SOC Alerts", 6, 6, 4),
    ("SOC Alerts by Severity", 12, 6, 7),
    ("Recent SOC Alert Timeline", 18, 6, 7),
])

add_section("21 - Latest SOC Alerts", [
    ("Latest SOC Alerts Table", 0, 24, 10),
])

# 12. Audit
add_section("22 - Audit & Administration", [
    ("Audit Log Timeline", 0, 16, 8),
    ("Audit Actions Summary", 16, 8, 8),
])

# Put any remaining panels at bottom so nothing is lost
remaining = [
    p for p in real_panels
    if p.get("title") not in used_titles
]

if remaining:
    new_panels.append(row_panel("99 - Other / Unsorted Panels", y))
    y += 1
    x = 0
    row_h = 8

    for p in remaining:
        title = p.get("title", "Untitled")
        print(f"[*] Keeping unsorted panel: {title}")
        new_panels.append(set_grid(p, x, y, 8, row_h))
        x += 8
        if x >= 24:
            x = 0
            y += row_h

dashboard["panels"] = new_panels
dashboard["title"] = "Advanced Honeypot SOC Dashboard - Clean Enterprise Layout"

payload = {
    "dashboard": dashboard,
    "folderId": meta.get("folderId", 0),
    "overwrite": True,
    "message": "Apply clean enterprise SOC dashboard layout",
}

result = api("POST", "/api/dashboards/db", payload)

print("[+] Clean dashboard layout applied.")
print("[+] Dashboard URL:", result.get("url", "open Grafana dashboard manually"))
