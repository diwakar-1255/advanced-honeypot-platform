MITRE_MAP = {
    "SSH Brute Force": "T1110 - Brute Force",
    "FTP Login Attempt": "T1110 - Brute Force",
    "SQL Injection": "T1190 - Exploit Public-Facing Application",
    "XSS": "T1190 - Exploit Public-Facing Application",
    "Path Traversal": "T1190 - Exploit Public-Facing Application",
    "Command Injection": "T1059 - Command and Scripting Interpreter",
    "Malware Download": "T1105 - Ingress Tool Transfer",
    "Scanner": "T1595 - Active Scanning"
}

def map_to_mitre(attack_type):
    return MITRE_MAP.get(attack_type, "Unmapped")
