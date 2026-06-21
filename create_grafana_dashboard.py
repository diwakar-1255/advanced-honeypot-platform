import json
import base64
import urllib.request
import urllib.parse

GRAFANA_URL = "http://localhost:3000"
USERNAME = "admin"
PASSWORD = "@#Diwa1255@#"
DATASOURCE_NAME = "grafana-postgresql-datasource-1"

auth = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()


def request_json(path, method="GET", data=None):
    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/json"
    }

    body = json.dumps(data).encode() if data is not None else None

    req = urllib.request.Request(
        GRAFANA_URL + path,
        data=body,
        headers=headers,
        method=method
    )

    with urllib.request.urlopen(req) as res:
        return json.loads(res.read().decode())


def get_datasource_uid(name):
    encoded_name = urllib.parse.quote(name)
    ds = request_json(f"/api/datasources/name/{encoded_name}")
    return ds["uid"]


def target(uid, sql, fmt="table"):
    return [
        {
            "refId": "A",
            "datasource": {
                "type": "postgres",
                "uid": uid
            },
            "rawSql": sql,
            "format": fmt,
            "editorMode": "code"
        }
    ]


def stat_panel(panel_id, title, sql, x, y, uid):
    return {
        "id": panel_id,
        "type": "stat",
        "title": title,
        "datasource": {"type": "postgres", "uid": uid},
        "gridPos": {"h": 4, "w": 6, "x": x, "y": y},
        "targets": target(uid, sql),
        "options": {
            "reduceOptions": {
                "values": False,
                "calcs": ["lastNotNull"],
                "fields": ""
            },
            "orientation": "auto",
            "textMode": "auto",
            "colorMode": "value",
            "graphMode": "area",
            "justifyMode": "auto"
        }
    }


def bar_panel(panel_id, title, sql, x, y, w, h, uid):
    return {
        "id": panel_id,
        "type": "barchart",
        "title": title,
        "datasource": {"type": "postgres", "uid": uid},
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": target(uid, sql),
        "options": {
            "orientation": "auto",
            "showValue": "auto",
            "stacking": "none"
        }
    }


def table_panel(panel_id, title, sql, x, y, w, h, uid):
    return {
        "id": panel_id,
        "type": "table",
        "title": title,
        "datasource": {"type": "postgres", "uid": uid},
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": target(uid, sql),
        "options": {
            "showHeader": True
        }
    }


def time_panel(panel_id, title, sql, x, y, w, h, uid):
    return {
        "id": panel_id,
        "type": "timeseries",
        "title": title,
        "datasource": {"type": "postgres", "uid": uid},
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": target(uid, sql, "time_series"),
        "options": {
            "legend": {
                "displayMode": "list",
                "placement": "bottom"
            },
            "tooltip": {
                "mode": "single"
            }
        }
    }


uid = get_datasource_uid(DATASOURCE_NAME)

dashboard = {
    "id": None,
    "uid": "advanced-honeypot-soc",
    "title": "Advanced Honeypot SOC Dashboard",
    "tags": ["honeypot", "soc", "cybersecurity"],
    "timezone": "browser",
    "schemaVersion": 39,
    "version": 0,
    "refresh": "10s",
    "time": {
        "from": "now-6h",
        "to": "now"
    },
    "panels": [
        stat_panel(
            1,
            "Total Events",
            "SELECT COUNT(*) AS total_events FROM events;",
            0,
            0,
            uid
        ),
        stat_panel(
            2,
            "Total Attackers",
            "SELECT COUNT(*) AS total_attackers FROM attackers;",
            6,
            0,
            uid
        ),
        stat_panel(
            3,
            "Total Alerts",
            "SELECT COUNT(*) AS total_alerts FROM alerts;",
            12,
            0,
            uid
        ),
        stat_panel(
            4,
            "Critical Alerts",
            "SELECT COUNT(*) AS critical_alerts FROM alerts WHERE severity = 'Critical';",
            18,
            0,
            uid
        ),
        bar_panel(
            5,
            "Events by Service",
            "SELECT service, COUNT(*) AS count FROM events GROUP BY service ORDER BY count DESC;",
            0,
            4,
            8,
            8,
            uid
        ),
        bar_panel(
            6,
            "Alerts by Severity",
            "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity ORDER BY CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC;",
            8,
            4,
            8,
            8,
            uid
        ),
        bar_panel(
            7,
            "Top Attack Types",
            "SELECT attack_type, COUNT(*) AS count FROM events WHERE attack_type IS NOT NULL GROUP BY attack_type ORDER BY count DESC;",
            16,
            4,
            8,
            8,
            uid
        ),
        time_panel(
            8,
            "Attack Timeline",
            "SELECT date_trunc('minute', timestamp) AS time, COUNT(*) AS events FROM events GROUP BY time ORDER BY time;",
            0,
            12,
            24,
            8,
            uid
        ),
        table_panel(
            9,
            "Recent SOC Alerts",
            "SELECT incident_id, source_ip, service, attack_type, severity, risk_score, occurrence_count, mitre_technique, status, updated_at FROM alerts ORDER BY updated_at DESC LIMIT 20;",
            0,
            20,
            24,
            9,
            uid
        ),
        table_panel(
            10,
            "Captured Credentials",
            "SELECT source_ip, service, username, password, attack_type, severity, timestamp FROM events WHERE username IS NOT NULL OR password IS NOT NULL ORDER BY timestamp DESC LIMIT 20;",
            0,
            29,
            12,
            9,
            uid
        ),
        bar_panel(
            11,
            "MITRE ATT&CK Mapping",
            "SELECT mitre_technique, COUNT(*) AS count FROM alerts WHERE mitre_technique IS NOT NULL GROUP BY mitre_technique ORDER BY count DESC;",
            12,
            29,
            12,
            9,
            uid
        ),
        table_panel(
            12,
            "Attacker Profiles",
            "SELECT source_ip, country, city, isp, asn, total_events, risk_score, severity, first_seen, last_seen FROM attackers ORDER BY risk_score DESC, total_events DESC LIMIT 20;",
            0,
            38,
            24,
            9,
            uid
        )
    ]
}

payload = {
    "dashboard": dashboard,
    "overwrite": True,
    "message": "Created Advanced Honeypot SOC Dashboard"
}

result = request_json("/api/dashboards/db", method="POST", data=payload)

print("Dashboard created successfully.")
print(GRAFANA_URL + "/d/advanced-honeypot-soc")
