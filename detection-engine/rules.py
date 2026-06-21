import re

RULES = {
    "SQL Injection": [r"(?i)union\s+select", r"(?i)'\s*or\s*'1'='1", r"(?i)sleep\("],
    "XSS": [r"(?i)<script", r"(?i)onerror\s*=", r"(?i)javascript:"],
    "Path Traversal": [r"\.\./", r"(?i)/etc/passwd", r"(?i)\.\.\%2f"],
    "Command Injection": [r";\s*whoami", r"&&\s*id", r"\|\s*cat"],
    "Malware Download": [r"(?i)wget\s+", r"(?i)curl\s+", r"(?i)\.sh", r"(?i)\.elf", r"(?i)\.exe"],
    "Scanner": [r"(?i)sqlmap", r"(?i)nikto", r"(?i)gobuster", r"(?i)nmap"]
}

def classify(text: str) -> str:
    for attack_type, patterns in RULES.items():
        if any(re.search(pattern, text or "") for pattern in patterns):
            return attack_type
    return "Unknown"
