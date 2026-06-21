import os
import json
import time
import socket
import hashlib
import threading
import urllib.request
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import paramiko
from paramiko import RSAKey, ServerInterface, AUTH_SUCCESSFUL, AUTH_FAILED, OPEN_SUCCEEDED


API_URL = os.getenv("CENTRAL_API_URL", "http://api:8000/events")

SSH_HOST = os.getenv("SSH_HOST", "0.0.0.0")
SSH_PORT = int(os.getenv("SSH_PORT", "2222"))

HOST_KEY_PATH = Path(os.getenv("SSH_HOST_KEY_PATH", "/app/ssh_host_rsa_key"))

FAILED_LOGINS = defaultdict(list)


FAKE_USERS = {
    "root": "toor",
    "admin": "admin123",
    "ubuntu": "ubuntu",
    "devops": "devops@123",
    "backup": "backup@123",
    "test": "test123",
    "oracle": "oracle",
}


SENSITIVE_WORDS = [
    "/etc/passwd",
    "/etc/shadow",
    ".env",
    "id_rsa",
    "authorized_keys",
    "config",
    "password",
    "passwd",
    "secret",
    "credential",
    "database",
    "backup",
    "wallet",
    "private",
]


MALWARE_WORDS = [
    "wget",
    "curl",
    "tftp",
    "ftp",
    "nc ",
    "netcat",
    "bash -i",
    "/dev/tcp",
    "chmod +x",
    "base64",
    "python -c",
    "perl -e",
    "powershell",
    "busybox",
    "miner",
    "xmrig",
]


PRIVESC_WORDS = [
    "sudo",
    "su ",
    "sudo -l",
    "pkexec",
    "passwd",
    "chmod 777",
    "chown root",
    "setuid",
]


PERSISTENCE_WORDS = [
    "crontab",
    "systemctl enable",
    "service ",
    "rc.local",
    ".bashrc",
    ".profile",
    "authorized_keys",
    "ssh-keygen",
]


def now_iso():
    return datetime.utcnow().isoformat()


def ensure_host_key():
    if HOST_KEY_PATH.exists():
        return RSAKey(filename=str(HOST_KEY_PATH))

    HOST_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = RSAKey.generate(2048)
    key.write_private_key_file(str(HOST_KEY_PATH))
    return key


HOST_KEY = ensure_host_key()


def detect_attack_type(event_type="", username="", command="", path=""):
    data = f"{event_type} {username} {command} {path}".lower()

    if "login failed" in data or "authentication failed" in data:
        return "Credential Attack"

    if any(word in data for word in SENSITIVE_WORDS):
        return "Sensitive File Access Attempt"

    if any(word in data for word in MALWARE_WORDS):
        return "Malware Download Attempt"

    if any(word in data for word in PRIVESC_WORDS):
        return "Privilege Escalation Attempt"

    if any(word in data for word in PERSISTENCE_WORDS):
        return "Persistence Attempt"

    if command:
        if command.split()[0] in ["whoami", "id", "uname", "hostname", "pwd", "ls", "ps", "netstat", "ss", "ip", "ifconfig"]:
            return "Reconnaissance"

        return "SSH Command Execution"

    return "SSH Probe"


def severity_score(attack_type, source_ip="unknown"):
    mapping = {
        "Credential Attack": ("Medium", 50),
        "Sensitive File Access Attempt": ("High", 75),
        "Malware Download Attempt": ("Critical", 90),
        "Privilege Escalation Attempt": ("High", 80),
        "Persistence Attempt": ("High", 85),
        "Reconnaissance": ("Medium", 45),
        "SSH Command Execution": ("Medium", 55),
        "SSH Probe": ("Low", 25),
    }

    severity, score = mapping.get(attack_type, ("Low", 20))

    recent = FAILED_LOGINS.get(source_ip, [])
    if len(recent) >= 5 and attack_type == "Credential Attack":
        severity = "High"
        score = max(score, 75)

    return severity, score


def send_event(
    source_ip="unknown",
    source_port=None,
    event_type="SSH Event",
    username=None,
    password=None,
    command=None,
    path=None,
    payload=None,
    attack_type=None,
):
    if attack_type is None:
        attack_type = detect_attack_type(
            event_type=event_type,
            username=username,
            command=command,
            path=path,
        )

    severity, risk_score = severity_score(attack_type, source_ip)

    event = {
        "timestamp": now_iso(),
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_port": SSH_PORT,
        "protocol": "TCP",
        "service": "SSH",
        "event_type": event_type,
        "username": username,
        "password": password,
        "command": command,
        "method": command,
        "path": path,
        "user_agent": "SSH Client",
        "payload": payload,
        "attack_type": attack_type,
        "severity": severity,
        "risk_score": risk_score,
        "raw_log": {
            "source_ip": source_ip,
            "source_port": source_port,
            "username": username,
            "command": command,
            "path": path,
            "payload": payload,
            "timestamp": now_iso(),
        },
    }

    try:
        req = urllib.request.Request(
            API_URL,
            data=json.dumps(event).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=4)
    except Exception as exc:
        print("Failed to send SSH event to API:", exc)

    print(json.dumps(event))


class AdvancedSSHServer(ServerInterface):
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.username = None
        self.authenticated = False
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        self.username = username

        if FAKE_USERS.get(username) == password:
            self.authenticated = True

            send_event(
                source_ip=self.client_ip,
                source_port=self.client_port,
                event_type="SSH Login Success",
                username=username,
                password=password,
                command="AUTH_PASSWORD",
                path="/",
                payload={"authenticated": True},
                attack_type="SSH Command Execution",
            )

            return AUTH_SUCCESSFUL

        FAILED_LOGINS[self.client_ip].append(time.time())
        FAILED_LOGINS[self.client_ip] = [
            ts for ts in FAILED_LOGINS[self.client_ip]
            if time.time() - ts <= 600
        ]

        send_event(
            source_ip=self.client_ip,
            source_port=self.client_port,
            event_type="SSH Login Failed",
            username=username,
            password=password,
            command="AUTH_PASSWORD",
            path="/",
            payload={
                "authenticated": False,
                "failed_count_10m": len(FAILED_LOGINS[self.client_ip]),
            },
            attack_type="Credential Attack",
        )

        return AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        decoded = command.decode(errors="ignore") if isinstance(command, bytes) else str(command)

        send_event(
            source_ip=self.client_ip,
            source_port=self.client_port,
            event_type="SSH Exec Command",
            username=self.username,
            command=decoded,
            path="/",
            payload={"exec_command": decoded},
        )

        response = fake_command_output(decoded, self.username or "root", "/home/" + (self.username or "root"))
        channel.send(response + "\n")
        channel.send_exit_status(0)
        self.event.set()
        return True


def fake_ls(path):
    entries = {
        "/": "bin  boot  dev  etc  home  lib  opt  root  tmp  usr  var\n",
        "/root": "backup.sh  credentials.txt  deploy.key  notes.txt\n",
        "/home/admin": "app  logs  scripts  README.md\n",
        "/home/ubuntu": "project  backup  logs  deploy.sh\n",
        "/etc": "passwd  shadow  ssh  nginx  crontab  hosts\n",
        "/var/log": "auth.log  syslog  nginx  audit.log\n",
        "/opt": "nexacloud  backup-agent  monitoring\n",
    }
    return entries.get(path, "README.md  backup.zip  config.yml  logs\n")


def fake_cat(target):
    target = target.strip()

    if target in ["/etc/passwd", "etc/passwd"]:
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash\n"
            "admin:x:1001:1001:admin:/home/admin:/bin/bash\n"
        )

    if target in ["/etc/shadow", "etc/shadow"]:
        return "cat: /etc/shadow: Permission denied\n"

    if ".env" in target or "config" in target:
        return (
            "APP_ENV=production\n"
            "DB_HOST=internal-db\n"
            "DB_USER=portal_app\n"
            "DB_PASSWORD=REDACTED_PLACEHOLDER\n"
        )

    if "credentials" in target or "password" in target:
        return "Access denied. This file is protected by enterprise policy.\n"

    if "auth.log" in target:
        return (
            "Jun 20 10:11:02 server sshd[2210]: Accepted password for admin from 10.10.10.5\n"
            "Jun 20 10:12:44 server sshd[2250]: Failed password for root from 185.22.10.9\n"
        )

    return f"cat: {target}: No such file or directory\n"


def fake_command_output(command, username, current_dir):
    cmd = command.strip()
    base = cmd.split()[0] if cmd else ""

    if cmd == "":
        return ""

    if base in ["exit", "logout"]:
        return "logout"

    if base == "whoami":
        return username

    if base == "id":
        if username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        return f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)"

    if base == "hostname":
        return "prod-ssh-gateway-01"

    if base == "uname":
        return "Linux prod-ssh-gateway-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"

    if base == "pwd":
        return current_dir

    if base == "ls":
        return fake_ls(current_dir)

    if base == "cat":
        target = cmd.replace("cat", "", 1).strip()
        return fake_cat(target)

    if base == "ps":
        return (
            "USER       PID %CPU %MEM COMMAND\n"
            "root         1  0.0  0.1 /sbin/init\n"
            "root       742  0.1  0.3 /usr/sbin/sshd -D\n"
            "postgres  981  0.2  1.2 postgres\n"
            "www-data 1211  0.1  0.8 nginx: worker process\n"
        )

    if base in ["netstat", "ss"]:
        return (
            "tcp   LISTEN 0 128 0.0.0.0:22    0.0.0.0:*\n"
            "tcp   LISTEN 0 128 0.0.0.0:80    0.0.0.0:*\n"
            "tcp   LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"
        )

    if base in ["ip", "ifconfig"]:
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>\n"
            "    inet 10.0.12.45 netmask 255.255.255.0 broadcast 10.0.12.255\n"
        )

    if base == "env":
        return (
            "APP_ENV=production\n"
            "REGION=india-south\n"
            "SERVICE=nexacloud-identity\n"
        )

    if base == "df":
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        40G   18G   20G  48% /\n"
        )

    if base == "free":
        return (
            "              total        used        free\n"
            "Mem:        2048000      922000      512000\n"
            "Swap:       1048576           0     1048576\n"
        )

    if base == "sudo":
        return "sudo: a password is required\n"

    if base in ["wget", "curl"]:
        return "Connecting... failed: network is unreachable\n"

    if base in ["chmod", "chown", "crontab", "systemctl"]:
        return "Operation not permitted\n"

    if base in ["clear"]:
        return "\033[2J\033[H"

    if base in ["help", "?"]:
        return "Available commands: ls, pwd, whoami, id, uname, hostname, cat, ps, ss, ip, env, df, free, exit"

    return f"{base}: command not found"


def handle_shell(channel, server):
    username = server.username or "root"
    current_dir = "/root" if username == "root" else f"/home/{username}"

    banner = (
        "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
        "\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n"
        "\r\n"
        "Last login: Sat Jun 20 10:22:14 2026 from 10.10.14.8\r\n"
    )

    channel.send(banner)
    prompt = f"{username}@prod-ssh-gateway-01:{current_dir}$ "
    channel.send(prompt)

    buffer = ""

    while True:
        try:
            data = channel.recv(1024)
            if not data:
                break

            for byte in data:
                ch = chr(byte)

                if ch in ["\r", "\n"]:
                    command = buffer.strip()
                    channel.send("\r\n")

                    if command:
                        send_event(
                            source_ip=server.client_ip,
                            source_port=server.client_port,
                            event_type="SSH Shell Command",
                            username=username,
                            command=command,
                            path=current_dir,
                            payload={"command": command, "cwd": current_dir},
                        )

                    if command.startswith("cd "):
                        target = command.replace("cd", "", 1).strip()

                        if target in ["", "~"]:
                            current_dir = "/root" if username == "root" else f"/home/{username}"
                        elif target.startswith("/"):
                            current_dir = target
                        elif target == "..":
                            current_dir = str(Path(current_dir).parent)
                        else:
                            current_dir = str(Path(current_dir) / target)

                        output = ""
                    else:
                        output = fake_command_output(command, username, current_dir)

                    if command in ["exit", "logout"]:
                        channel.send("logout\r\n")
                        return

                    if output:
                        channel.send(output.replace("\n", "\r\n") + "\r\n")

                    prompt = f"{username}@prod-ssh-gateway-01:{current_dir}$ "
                    channel.send(prompt)
                    buffer = ""

                elif ch == "\x7f" or ch == "\b":
                    buffer = buffer[:-1]
                    channel.send("\b \b")

                elif ch == "\x03":
                    buffer = ""
                    channel.send("^C\r\n")
                    prompt = f"{username}@prod-ssh-gateway-01:{current_dir}$ "
                    channel.send(prompt)

                else:
                    buffer += ch
                    channel.send(ch)

        except Exception:
            break


def handle_client(client_socket, address):
    client_ip, client_port = address

    send_event(
        source_ip=client_ip,
        source_port=client_port,
        event_type="SSH Connection Opened",
        command="CONNECT",
        path="/",
        payload={"banner": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
        attack_type="SSH Probe",
    )

    transport = paramiko.Transport(client_socket)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    transport.add_server_key(HOST_KEY)

    server = AdvancedSSHServer(client_ip, client_port)

    try:
        transport.start_server(server=server)
        channel = transport.accept(20)

        if channel is None:
            transport.close()
            return

        server.event.wait(10)

        if server.authenticated:
            handle_shell(channel, server)

    except Exception as exc:
        print(f"SSH client handler error from {client_ip}:{client_port}: {exc}")

    finally:
        send_event(
            source_ip=client_ip,
            source_port=client_port,
            event_type="SSH Connection Closed",
            username=server.username,
            command="DISCONNECT",
            path="/",
            attack_type="SSH Probe",
        )

        try:
            transport.close()
        except Exception:
            pass


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SSH_HOST, SSH_PORT))
    sock.listen(100)

    print(f"Advanced SSH Honeypot running on {SSH_HOST}:{SSH_PORT}")
    print("Fake users:")
    for user in FAKE_USERS:
        print(f" - {user}")

    while True:
        client, addr = sock.accept()
        thread = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
        thread.start()


if __name__ == "__main__":
    main()
