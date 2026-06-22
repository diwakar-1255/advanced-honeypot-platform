import os
import json
import base64
import urllib.request
import urllib.error

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

def get_postgres_uid():
    datasources = api("GET", "/api/datasources")
    for ds in datasources:
        if ds.get("type") in ("postgres", "grafana-postgresql-datasource"):
            print("[+] Using datasource:", ds.get("name"), ds.get("uid"))
            return ds["uid"], ds.get("type")
    raise SystemExit("No PostgreSQL datasource found")

DS_UID, DS_TYPE = get_postgres_uid()

def target(sql, ref="A", fmt="table"):
    return {
        "refId": ref,
        "datasource": {"type": DS_TYPE, "uid": DS_UID},
        "format": fmt,
        "rawQuery": True,
        "rawSql": sql,
    }

resp = api("GET", f"/api/dashboards/uid/{DASHBOARD_UID}")
dashboard = resp["dashboard"]
meta = resp.get("meta", {})

panels = dashboard.setdefault("panels", [])

remove_titles = {
    "Open SOC Alerts",
    "Critical SOC Alerts",
    "SOC Alerts by Severity",
    "Recent SOC Alert Timeline",
    "Latest SOC Alerts Table",
}

panels[:] = [p for p in panels if p.get("title") not in remove_titles]

base_y = 0
if panels:
    base_y = max(
        p.get("gridPos", {}).get("y", 0) + p.get("gridPos", {}).get("h", 0)
        for p in panels
    ) + 1

new_panels = [
    {
        "id": 9201,
        "type": "stat",
        "title": "Open SOC Alerts",
        "datasource": {"type": DS_TYPE, "uid": DS_UID},
        "gridPos": {"h": 6, "w": 6, "x": 0, "y": base_y},
        "targets": [
            target("""
                SELECT COUNT(*) AS open_soc_alerts
                FROM soc_alerts
                WHERE status = 'Open';
            """)
        ],
        "fieldConfig": {
            "defaults": {
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": "green", "value": None},
                        {"color": "orange", "value": 1},
                        {"color": "red", "value": 5}
                    ]
                }
            },
            "overrides": []
        },
        "options": {
            "reduceOptions": {
                "calcs": ["lastNotNull"],
                "fields": "",
                "values": False
            }
        },
    },
    {
        "id": 9202,
        "type": "stat",
        "title": "Critical SOC Alerts",
        "datasource": {"type": DS_TYPE, "uid": DS_UID},
        "gridPos": {"h": 6, "w": 6, "x": 6, "y": base_y},
        "targets": [
            target("""
                SELECT COUNT(*) AS critical_soc_alerts
                FROM soc_alerts
                WHERE severity = 'Critical'
                  AND status = 'Open';
            """)
        ],
        "fieldConfig": {
            "defaults": {
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": "green", "value": None},
                        {"color": "red", "value": 1}
                    ]
                }
            },
            "overrides": []
        },
        "options": {
            "reduceOptions": {
                "calcs": ["lastNotNull"],
                "fields": "",
                "values": False
            }
        },
    },
    {
        "id": 9203,
        "type": "barchart",
        "title": "SOC Alerts by Severity",
        "datasource": {"type": DS_TYPE, "uid": DS_UID},
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": base_y},
        "targets": [
            target("""
                SELECT severity, COUNT(*) AS alert_count
                FROM soc_alerts
                GROUP BY severity
                ORDER BY alert_count DESC;
            """)
        ],
    },
    {
        "id": 9204,
        "type": "timeseries",
        "title": "Recent SOC Alert Timeline",
        "datasource": {"type": DS_TYPE, "uid": DS_UID},
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": base_y + 6},
        "targets": [
            target("""
                SELECT
                  date_trunc('minute', created_at) AS time,
                  COUNT(*) AS alerts
                FROM soc_alerts
                WHERE created_at >= NOW() - INTERVAL '24 hours'
                GROUP BY 1
                ORDER BY 1;
            """, fmt="time_series")
        ],
    },
    {
        "id": 9205,
        "type": "table",
        "title": "Latest SOC Alerts Table",
        "datasource": {"type": DS_TYPE, "uid": DS_UID},
        "gridPos": {"h": 10, "w": 12, "x": 12, "y": base_y + 6},
        "targets": [
            target("""
                SELECT
                  created_at,
                  rule_name,
                  severity,
                  matched_count,
                  status,
                  description
                FROM soc_alerts
                ORDER BY created_at DESC
                LIMIT 50;
            """)
        ],
        "options": {"showHeader": True},
    },
]

panels.extend(new_panels)

payload = {
    "dashboard": dashboard,
    "folderId": meta.get("folderId", 0),
    "overwrite": True,
    "message": "Add SOC alert panels",
}

result = api("POST", "/api/dashboards/db", payload)

print("[+] SOC alert panels added successfully.")
print("[+] Dashboard URL:", result.get("url", "open Grafana dashboard manually"))
