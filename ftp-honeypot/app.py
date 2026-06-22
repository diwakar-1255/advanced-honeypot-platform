import os
import json
import time
import hashlib
import urllib.request
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
HONEYPOT_API_TOKEN = os.getenv("HONEYPOT_API_TOKEN", "")

def honeypot_auth_headers():
    headers = {"Content-Type": "application/json"}
    if HONEYPOT_API_TOKEN:
        headers["X-Honeypot-Token"] = HONEYPOT_API_TOKEN
    return headers



API_URL = os.getenv("CENTRAL_API_URL", "http://api:8000/events")
FTP_HOST = os.getenv("FTP_HOST", "0.0.0.0")
FTP_PORT = int(os.getenv("FTP_PORT", "2121"))

ROOT_DIR = Path(os.getenv("FTP_ROOT_DIR", "/tmp/enterprise-ftp-root"))
UPLOAD_DIR = Path(os.getenv("FTP_UPLOAD_DIR", "/tmp/enterprise-ftp-uploads"))

PASSIVE_START = int(os.getenv("FTP_PASSIVE_START", "30000"))
PASSIVE_END = int(os.getenv("FTP_PASSIVE_END", "30009"))

FAILED_LOGINS = defaultdict(list)

FAKE_USERS = {
    "admin": "admin123",
    "backup": "backup@123",
    "ftpuser": "ftpuser123",
    "audit": "audit2026",
    "devops": "devops@123",
    "root": "root",
    "test": "test123",
}


def now_iso():
    return datetime.utcnow().isoformat()


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def file_size(path):
    try:
        return os.path.getsize(path)
    except Exception:
        return 0


def detect_attack(event_type="", username="", command="", path="", user_agent="FTP Client"):
    data = f"{event_type} {username} {command} {path} {user_agent}".lower()

    if "../" in data or "..\\" in data or "/etc/passwd" in data or "boot.ini" in data:
        return "Path Traversal"

    sensitive_words = [
        "password", "passwd", "shadow", "secret", "credential",
        "database", "backup", "config", ".env", "id_rsa",
        ".git", "admin", "private", "dump"
    ]

    if any(word in data for word in sensitive_words):
        return "Sensitive File Access Attempt"

    if any(tool in data for tool in ["hydra", "nmap", "ncrack", "medusa", "masscan", "metasploit"]):
        return "Scanner"

    if "login failed" in data:
        return "Credential Attack"

    if "login success" in data:
        return "FTP Login Attempt"

    if "stor" in data or "upload" in data or "file received" in data:
        return "File Upload Attempt"

    if "retr" in data or "download" in data or "file sent" in data:
        return "FTP File Access"

    return "FTP Probe"


def severity_score(attack_type, source_ip="unknown"):
    mapping = {
        "Path Traversal": ("High", 75),
        "Sensitive File Access Attempt": ("High", 70),
        "Credential Attack": ("Medium", 50),
        "FTP Login Attempt": ("Medium", 45),
        "File Upload Attempt": ("High", 80),
        "FTP File Access": ("Medium", 45),
        "Scanner": ("Medium", 45),
        "FTP Probe": ("Low", 25),
    }

    severity, score = mapping.get(attack_type, ("Low", 20))

    if source_ip in FAILED_LOGINS and len(FAILED_LOGINS[source_ip]) >= 5:
        severity = "High"
        score = max(score, 70)

    return severity, score


def send_event(handler, event_type, username=None, password=None, command=None, path=None, payload=None, attack_type=None):
    source_ip = getattr(handler, "remote_ip", "unknown")
    source_port = getattr(handler, "remote_port", None)

    if attack_type is None:
        attack_type = detect_attack(
            event_type=event_type,
            username=username,
            command=command,
            path=path,
            user_agent="FTP Client"
        )

    severity, risk_score = severity_score(attack_type, source_ip)

    event = {
        "timestamp": now_iso(),
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_port": FTP_PORT,
        "protocol": "TCP",
        "service": "FTP",
        "event_type": event_type,
        "username": username,
        "password": password,
        "command": command,
        "method": command,
        "path": path,
        "user_agent": "FTP Client",
        "payload": payload,
        "attack_type": attack_type,
        "severity": severity,
        "risk_score": risk_score,
        "raw_log": {
            "source_ip": source_ip,
            "source_port": source_port,
            "ftp_command": command,
            "path": path,
            "payload": payload,
            "timestamp": now_iso()
        }
    }

    try:
        req = urllib.request.Request(
            API_URL,
            data=json.dumps(event).encode("utf-8"),
            headers=honeypot_auth_headers(),
            method="POST"
        )
        urllib.request.urlopen(req, timeout=4)
    except Exception as exc:
        print("Failed to send FTP event to API:", exc)

    print(json.dumps(event))


def write_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def prepare_files():
    ROOT_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    write_file(
        ROOT_DIR / "README.txt",
        """NexaCloud Enterprise FTP Gateway

Authorized access only.
All access attempts and file transfers are monitored.
"""
    )

    write_file(
        ROOT_DIR / "backups" / "database_backup_2026.sql",
        """-- Enterprise Database Backup Placeholder
-- Restore Point: 2026-06-20
-- Classification: Confidential
"""
    )

    write_file(
        ROOT_DIR / "backups" / "server_backup_manifest.txt",
        """server01.tar.gz
portal-db.sql
identity-service-config.yml
vpn-users-export.csv
"""
    )

    write_file(
        ROOT_DIR / "configs" / "app_config.ini",
        """[production]
environment=production
database=internal-db
debug=false
backup_enabled=true
"""
    )

    write_file(
        ROOT_DIR / "configs" / ".env",
        """APP_ENV=production
DB_HOST=internal-db
DB_USER=portal_app
DB_PASSWORD=REDACTED_PLACEHOLDER
"""
    )

    write_file(
        ROOT_DIR / "logs" / "vpn_access.log",
        """2026-06-20 09:10:11 VPN login success user=audit
2026-06-20 10:15:30 VPN login failed user=admin
2026-06-20 11:22:40 Backup sync completed
"""
    )

    write_file(
        ROOT_DIR / "admin" / "password_policy.txt",
        """Password Policy:
Minimum length: 14
MFA: Required
Privileged access: Restricted
"""
    )

    write_file(
        ROOT_DIR / "uploads" / "upload_instructions.txt",
        """Upload area for scheduled backup packages.
Unexpected uploads are quarantined and reviewed.
"""
    )


class AdvancedFTPHandler(FTPHandler):
    banner = "NexaCloud Enterprise FTP Gateway v4.2 - Authorized Access Only"

    def on_connect(self):
        send_event(
            self,
            event_type="FTP Connection Opened",
            command="CONNECT",
            path="/",
            payload={"banner": self.banner},
            attack_type="FTP Probe"
        )

    def on_disconnect(self):
        send_event(
            self,
            event_type="FTP Connection Closed",
            username=getattr(self, "username", None),
            command="DISCONNECT",
            path="/",
            attack_type="FTP Probe"
        )

    def on_login(self, username):
        send_event(
            self,
            event_type="FTP Login Success",
            username=username,
            command="LOGIN",
            path="/",
            payload={"authenticated": True},
            attack_type="FTP Login Attempt"
        )

    def on_login_failed(self, username, password):
        source_ip = getattr(self, "remote_ip", "unknown")
        FAILED_LOGINS[source_ip].append(time.time())

        FAILED_LOGINS[source_ip] = [
            ts for ts in FAILED_LOGINS[source_ip]
            if time.time() - ts <= 600
        ]

        send_event(
            self,
            event_type="FTP Login Failed",
            username=username,
            password=password,
            command="USER/PASS",
            path="/",
            payload={
                "username": username,
                "password": password,
                "failed_count_10m": len(FAILED_LOGINS[source_ip])
            },
            attack_type="Credential Attack"
        )

    def log_cmd(self, cmd, arg, respcode, respstr):
        try:
            super().log_cmd(cmd, arg, respcode, respstr)
        except Exception:
            pass

        username = getattr(self, "username", None)
        command_text = f"{cmd} {arg or ''}".strip()

        important = {
            "USER", "PASS", "LIST", "NLST", "CWD", "PWD",
            "RETR", "STOR", "DELE", "MKD", "RMD", "RNFR",
            "RNTO", "SITE", "SYST", "FEAT"
        }

        attack_type = detect_attack(
            event_type="FTP Command",
            username=username,
            command=command_text,
            path=arg
        )

        if cmd in important or attack_type != "FTP Probe":
            send_event(
                self,
                event_type="FTP Command",
                username=username,
                command=cmd,
                path=arg,
                payload={
                    "command": cmd,
                    "argument": arg,
                    "response_code": respcode,
                    "response": respstr
                },
                attack_type=attack_type
            )

    def ftp_RETR(self, file):
        send_event(
            self,
            event_type="FTP File Download Attempt",
            username=getattr(self, "username", None),
            command="RETR",
            path=file,
            payload={"file": file},
            attack_type=detect_attack(
                event_type="FTP File Download Attempt",
                username=getattr(self, "username", None),
                command="RETR",
                path=file
            )
        )
        return super().ftp_RETR(file)

    def ftp_STOR(self, file, mode="w"):
        send_event(
            self,
            event_type="FTP File Upload Attempt",
            username=getattr(self, "username", None),
            command="STOR",
            path=file,
            payload={"file": file, "mode": mode},
            attack_type="File Upload Attempt"
        )
        return super().ftp_STOR(file, mode)

    def on_file_sent(self, file):
        send_event(
            self,
            event_type="FTP File Sent",
            username=getattr(self, "username", None),
            command="RETR",
            path=file,
            payload={
                "file": file,
                "size": file_size(file),
                "sha256": sha256_file(file)
            },
            attack_type=detect_attack(
                event_type="FTP File Sent",
                username=getattr(self, "username", None),
                command="RETR",
                path=file
            )
        )

    def on_file_received(self, file):
        uploaded = Path(file)
        size = file_size(uploaded)
        file_hash = sha256_file(uploaded)

        quarantine_name = f"{int(time.time())}_{uploaded.name}"
        quarantine_path = UPLOAD_DIR / quarantine_name

        try:
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            uploaded.replace(quarantine_path)
            quarantine_path.chmod(0o600)

            payload = {
                "original_file": str(file),
                "quarantine_file": str(quarantine_path),
                "size": size,
                "sha256": file_hash,
                "action": "quarantined"
            }

        except Exception as exc:
            payload = {
                "file": str(file),
                "size": size,
                "sha256": file_hash,
                "quarantine_error": str(exc)
            }

        send_event(
            self,
            event_type="FTP File Received",
            username=getattr(self, "username", None),
            command="STOR",
            path=file,
            payload=payload,
            attack_type="File Upload Attempt"
        )


def build_authorizer():
    authorizer = DummyAuthorizer()

    for username, password in FAKE_USERS.items():
        authorizer.add_user(
            username=username,
            password=password,
            homedir=str(ROOT_DIR),
            perm="elradfmwMT"
        )

    authorizer.add_anonymous(
        homedir=str(ROOT_DIR),
        perm="elr"
    )

    return authorizer


def main():
    prepare_files()

    handler = AdvancedFTPHandler
    handler.authorizer = build_authorizer()
    handler.passive_ports = range(PASSIVE_START, PASSIVE_END + 1)

    address = (FTP_HOST, FTP_PORT)
    server = FTPServer(address, handler)

    print(f"Advanced FTP Honeypot running on {FTP_HOST}:{FTP_PORT}")
    print(f"FTP root: {ROOT_DIR}")
    print(f"Upload quarantine: {UPLOAD_DIR}")
    print(f"Passive ports: {PASSIVE_START}-{PASSIVE_END}")

    server.serve_forever()


if __name__ == "__main__":
    main()
