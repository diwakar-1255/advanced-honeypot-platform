import os
import sys
import requests

GRAFANA_URL = os.getenv("GRAFANA_URL", "http://localhost:3000")
GRAFANA_USER = os.getenv("GRAFANA_ADMIN_USER", "admin")
GRAFANA_PASSWORD = os.getenv("GRAFANA_ADMIN_PASSWORD", "")
DASHBOARD_UID = os.getenv("GRAFANA_DASHBOARD_UID", "advanced-honeypot-soc")

if not GRAFANA_PASSWORD:
    print("[-] GRAFANA_ADMIN_PASSWORD is not set")
    sys.exit(1)

session = requests.Session()
session.auth = (GRAFANA_USER, GRAFANA_PASSWORD)
session.headers.update({"Content-Type": "application/json"})

r = session.get(f"{GRAFANA_URL}/api/dashboards/uid/{DASHBOARD_UID}", timeout=30)
r.raise_for_status()

data = r.json()
dashboard = data["dashboard"]
folder_id = data.get("meta", {}).get("folderId", 0)

dashboard["refresh"] = "30s"

# Keep existing panels exactly as they are.
payload = {
    "dashboard": dashboard,
    "folderId": folder_id,
    "overwrite": True,
    "message": "Optimize dashboard refresh rate"
}

r = session.post(f"{GRAFANA_URL}/api/dashboards/db", json=payload, timeout=60)
r.raise_for_status()

print("[+] Dashboard refresh changed to 30s without changing panels")
print("[+] URL:", r.json().get("url"))
