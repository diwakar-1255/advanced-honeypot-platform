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


def get_datasource_uid():
    r = session.get(f"{GRAFANA_URL}/api/datasources")
    r.raise_for_status()
    datasources = r.json()

    print("[*] Available Grafana datasources:")
    for ds in datasources:
        print("   -", ds.get("name"), "|", ds.get("type"), "|", ds.get("uid"))

    for ds in datasources:
        name = str(ds.get("name", "")).lower()
        ds_type = str(ds.get("type", "")).lower()
        uid = str(ds.get("uid", "")).lower()

        if (
            "postgres" in name
            or "postgresql" in name
            or "postgres" in ds_type
            or "postgresql" in ds_type
            or "postgres" in uid
            or "postgresql" in uid
        ):
            print("[+] Using PostgreSQL datasource:", ds.get("name"), ds.get("uid"))
            return ds["uid"]

    print("[-] PostgreSQL datasource not found")
    sys.exit(1)


def get_dashboard():
    r = session.get(f"{GRAFANA_URL}/api/dashboards/uid/{DASHBOARD_UID}")
    r.raise_for_status()
    data = r.json()
    return data["dashboard"], data.get("meta", {}).get("folderId", 0)


def target(sql, datasource_uid):
    return {
        "datasource": {"type": "postgres", "uid": datasource_uid},
        "format": "table",
        "rawSql": sql,
        "refId": "A"
    }


def table_panel(panel_id, title, x, y, w, h, sql, datasource_uid):
    return {
        "id": panel_id,
        "type": "table",
        "title": title,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "datasource": {"type": "postgres", "uid": datasource_uid},
        "targets": [target(sql, datasource_uid)],
        "options": {
            "showHeader": True,
            "cellHeight": "sm",
            "footer": {"show": False}
        }
    }


def stat_panel(panel_id, title, x, y, w, h, sql, datasource_uid):
    return {
        "id": panel_id,
        "type": "stat",
        "title": title,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "datasource": {"type": "postgres", "uid": datasource_uid},
        "targets": [target(sql, datasource_uid)],
        "options": {
            "reduceOptions": {
                "values": False,
                "calcs": ["lastNotNull"],
                "fields": ""
            },
            "orientation": "auto",
            "textMode": "auto",
            "colorMode": "value",
            "graphMode": "none"
        }
    }


def row_panel(panel_id, title, y):
    return {
        "id": panel_id,
        "type": "row",
        "title": title,
        "collapsed": False,
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
        "panels": []
    }


def text_panel(panel_id, title, x, y, w, h, content):
    return {
        "id": panel_id,
        "type": "text",
        "title": title,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "options": {
            "mode": "markdown",
            "content": content
        }
    }


def main():
    ds_uid = get_datasource_uid()
    dashboard, folder_id = get_dashboard()

    panels = dashboard.get("panels", [])

    # Remove old investigation panels if rerun
    panels = [
        p for p in panels
        if not str(p.get("title", "")).startswith("23 -")
        and "Investigation Center" not in str(p.get("title", ""))
        and "IOC Correlation" not in str(p.get("title", ""))
        and "Session Replay" not in str(p.get("title", ""))
        and "Evidence Export" not in str(p.get("title", ""))
    ]

    max_y = 0
    max_id = 0
    for p in panels:
        gp = p.get("gridPos", {})
        max_y = max(max_y, gp.get("y", 0) + gp.get("h", 0))
        max_id = max(max_id, int(p.get("id", 0) or 0))

    def next_id():
        nonlocal max_id
        max_id += 1
        return max_id

    def filter_clause(table_alias=""):
        prefix = f"{table_alias}." if table_alias else ""
        return f"""
        $__timeFilter({prefix}event_time)
        AND (
            '${{search_text}}' = ''
            OR {prefix}source_ip ILIKE '%' || '${{search_text}}' || '%'
            OR {prefix}country ILIKE '%' || '${{search_text}}' || '%'
            OR {prefix}username ILIKE '%' || '${{search_text}}' || '%'
            OR {prefix}attack_type ILIKE '%' || '${{search_text}}' || '%'
            OR {prefix}mitre_id ILIKE '%' || '${{search_text}}' || '%'
            OR {prefix}mitre_technique ILIKE '%' || '${{search_text}}' || '%'
        )
        AND ('${{country_filter}}' = '' OR {prefix}country ILIKE '%' || '${{country_filter}}' || '%')
        AND ('${{username_filter}}' = '' OR {prefix}username ILIKE '%' || '${{username_filter}}' || '%')
        AND ('${{attack_type_filter}}' = '' OR {prefix}attack_type ILIKE '%' || '${{attack_type_filter}}' || '%')
        AND ('${{mitre_filter}}' = '' OR {prefix}mitre_id ILIKE '%' || '${{mitre_filter}}' || '%' OR {prefix}mitre_technique ILIKE '%' || '${{mitre_filter}}' || '%')
        AND {prefix}risk_score >= COALESCE(NULLIF('${{risk_min}}', '')::int, 0)
        """

    y = max_y + 1

    panels.append(row_panel(next_id(), "23 - Attacker Investigation Center", y))
    y += 1

    panels.append(text_panel(
        next_id(),
        "Investigation Center Search Help",
        0, y, 24, 3,
        """
### Attacker Investigation Center

Use dashboard variables at the top:

- **search_text**: IP / country / username / attack type / MITRE ID
- **country_filter**: filter by country
- **username_filter**: filter by username
- **attack_type_filter**: filter by attack type
- **mitre_filter**: filter by MITRE technique
- **risk_min**: minimum risk score, example `80`
- Use Grafana time picker for date range, such as Last 24 hours or Last 7 days.
"""
    ))
    y += 3

    panels.append(stat_panel(
        next_id(),
        "Investigation Total Events",
        0, y, 6, 4,
        f"""
        SELECT COUNT(*) AS total_events
        FROM attacker_investigation_events
        WHERE {filter_clause()}
        """,
        ds_uid
    ))

    panels.append(stat_panel(
        next_id(),
        "Investigation Unique Attackers",
        6, y, 6, 4,
        f"""
        SELECT COUNT(DISTINCT source_ip) AS unique_attackers
        FROM attacker_investigation_events
        WHERE {filter_clause()}
        """,
        ds_uid
    ))

    panels.append(stat_panel(
        next_id(),
        "Investigation Max Risk",
        12, y, 6, 4,
        f"""
        SELECT COALESCE(MAX(risk_score), 0) AS max_risk_score
        FROM attacker_investigation_events
        WHERE {filter_clause()}
        """,
        ds_uid
    ))

    panels.append(stat_panel(
        next_id(),
        "Correlated Multi-Service Attackers",
        18, y, 6, 4,
        f"""
        SELECT COUNT(*) AS multi_service_attackers
        FROM (
            SELECT source_ip
            FROM attacker_investigation_events
            WHERE {filter_clause()}
            GROUP BY source_ip
            HAVING COUNT(DISTINCT service) >= 2
        ) x
        """,
        ds_uid
    ))
    y += 4

    panels.append(table_panel(
        next_id(),
        "Attacker Profile Page - Summary",
        0, y, 24, 8,
        f"""
        SELECT
            source_ip AS "IP",
            MAX(country) AS "Country",
            MAX(city) AS "City",
            MAX(asn) AS "ASN",
            MIN(event_time) AS "First Seen",
            MAX(event_time) AS "Last Seen",
            COUNT(*) AS "Total Attacks",
            COUNT(*) FILTER (WHERE service = 'SSH') AS "SSH",
            COUNT(*) FILTER (WHERE service = 'FTP') AS "FTP",
            COUNT(*) FILTER (WHERE service IN ('HTTP', 'HTTPS')) AS "WEB",
            COUNT(DISTINCT service) AS "Services",
            MAX(risk_score) AS "Risk Score",
            STRING_AGG(DISTINCT attack_type, ', ' ORDER BY attack_type) AS "Attack Types",
            STRING_AGG(DISTINCT mitre_id, ', ' ORDER BY mitre_id) FILTER (WHERE mitre_id <> '-') AS "MITRE Techniques"
        FROM attacker_investigation_events
        WHERE {filter_clause()}
        GROUP BY source_ip
        ORDER BY "Risk Score" DESC, "Total Attacks" DESC
        LIMIT 50;
        """,
        ds_uid
    ))
    y += 8

    panels.append(table_panel(
        next_id(),
        "IOC Correlation by Service",
        0, y, 12, 8,
        f"""
        SELECT
            source_ip AS "IP",
            MAX(country) AS "Country",
            COUNT(*) FILTER (WHERE service = 'SSH') AS "SSH",
            COUNT(*) FILTER (WHERE service = 'FTP') AS "FTP",
            COUNT(*) FILTER (WHERE service IN ('HTTP', 'HTTPS')) AS "WEB",
            COUNT(DISTINCT service) AS "Correlated Services",
            COUNT(*) AS "Total",
            MAX(risk_score) AS "Max Risk"
        FROM attacker_investigation_events
        WHERE {filter_clause()}
        GROUP BY source_ip
        HAVING COUNT(DISTINCT service) >= 2
        ORDER BY "Correlated Services" DESC, "Max Risk" DESC, "Total" DESC
        LIMIT 50;
        """,
        ds_uid
    ))

    panels.append(table_panel(
        next_id(),
        "MITRE Techniques for Investigation",
        12, y, 12, 8,
        f"""
        SELECT
            mitre_id AS "MITRE ID",
            mitre_tactic AS "Tactic",
            mitre_technique AS "Technique",
            COUNT(*) AS "Events",
            COUNT(DISTINCT source_ip) AS "Attackers",
            MAX(risk_score) AS "Max Risk"
        FROM attacker_investigation_events
        WHERE {filter_clause()}
          AND mitre_id <> '-'
        GROUP BY mitre_id, mitre_tactic, mitre_technique
        ORDER BY "Max Risk" DESC, "Events" DESC
        LIMIT 50;
        """,
        ds_uid
    ))
    y += 8

    panels.append(table_panel(
        next_id(),
        "Investigation Timeline",
        0, y, 24, 10,
        f"""
        SELECT
            event_time AS "Time",
            source_ip AS "IP",
            country AS "Country",
            service AS "Service",
            attacker_action AS "Action",
            attack_type AS "Attack Type",
            username AS "Username",
            mitre_id AS "MITRE",
            risk_score AS "Risk",
            severity AS "Severity"
        FROM attacker_investigation_timeline
        WHERE {filter_clause()}
        ORDER BY event_time ASC
        LIMIT 300;
        """,
        ds_uid
    ))
    y += 10

    panels.append(table_panel(
        next_id(),
        "Web Session Replay",
        0, y, 12, 10,
        f"""
        SELECT
            event_time AS "Time",
            source_ip AS "IP",
            sequence_no AS "Step",
            method AS "Method",
            path AS "Path",
            attack_type AS "Attack Type",
            risk_score AS "Risk",
            user_agent AS "User Agent"
        FROM attacker_web_session_replay
        WHERE {filter_clause()}
        ORDER BY source_ip, event_time ASC
        LIMIT 300;
        """,
        ds_uid
    ))

    panels.append(table_panel(
        next_id(),
        "Evidence Export Table",
        12, y, 12, 10,
        f"""
        SELECT
            event_time AS "Time",
            source_ip AS "IP",
            country AS "Country",
            service AS "Service",
            event_type AS "Event Type",
            attack_type AS "Attack Type",
            username AS "Username",
            method AS "Method",
            path AS "Path",
            command AS "Command",
            mitre_id AS "MITRE",
            mitre_technique AS "Technique",
            risk_score AS "Risk",
            severity AS "Severity"
        FROM attacker_investigation_events
        WHERE {filter_clause()}
        ORDER BY event_time DESC
        LIMIT 1000;
        """,
        ds_uid
    ))

    dashboard["panels"] = panels

    templating = dashboard.setdefault("templating", {}).setdefault("list", [])

    existing_names = {v.get("name") for v in templating}

    variables = [
        {
            "name": "search_text",
            "type": "textbox",
            "label": "Investigation Search",
            "query": "",
            "current": {"text": "", "value": ""},
            "hide": 0
        },
        {
            "name": "country_filter",
            "type": "textbox",
            "label": "Country",
            "query": "",
            "current": {"text": "", "value": ""},
            "hide": 0
        },
        {
            "name": "username_filter",
            "type": "textbox",
            "label": "Username",
            "query": "",
            "current": {"text": "", "value": ""},
            "hide": 0
        },
        {
            "name": "attack_type_filter",
            "type": "textbox",
            "label": "Attack Type",
            "query": "",
            "current": {"text": "", "value": ""},
            "hide": 0
        },
        {
            "name": "mitre_filter",
            "type": "textbox",
            "label": "MITRE",
            "query": "",
            "current": {"text": "", "value": ""},
            "hide": 0
        },
        {
            "name": "risk_min",
            "type": "textbox",
            "label": "Min Risk",
            "query": "0",
            "current": {"text": "0", "value": "0"},
            "hide": 0
        }
    ]

    for var in variables:
        if var["name"] not in existing_names:
            templating.append(var)

    dashboard["title"] = "Advanced Honeypot SOC Dashboard - Clean Enterprise Layout"
    dashboard["uid"] = DASHBOARD_UID

    payload = {
        "dashboard": dashboard,
        "folderId": folder_id,
        "overwrite": True,
        "message": "Add Attacker Investigation Center"
    }

    r = session.post(f"{GRAFANA_URL}/api/dashboards/db", json=payload)
    r.raise_for_status()

    print("[+] Attacker Investigation Center added to Grafana dashboard")
    print("[+] Dashboard URL:", r.json().get("url"))


if __name__ == "__main__":
    main()
