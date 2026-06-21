def calculate_risk(event):
    score = 0

    username = (event.get("username") or "").lower()
    payload = (event.get("payload") or "").lower()
    command = (event.get("command") or "").lower()
    attack_type = event.get("attack_type") or ""

    if username in ["root", "admin", "administrator", "ubuntu", "test"]:
        score += 10

    if attack_type in ["SQL Injection", "XSS", "Path Traversal"]:
        score += 20

    if attack_type == "Command Injection":
        score += 30

    if "wget" in command or "curl" in command or "wget" in payload or "curl" in payload:
        score += 25

    if attack_type == "Scanner":
        score += 15

    score = min(score, 100)

    if score >= 81:
        severity = "Critical"
    elif score >= 61:
        severity = "High"
    elif score >= 31:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity
