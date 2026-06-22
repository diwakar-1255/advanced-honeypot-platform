#!/usr/bin/env python3
import os
import re
import json
import hashlib
import shutil
import subprocess
from datetime import datetime

FTP_CONTAINER = "ftp-honeypot"
POSTGRES_CONTAINER = "honeypot-postgres"
POSTGRES_USER = "honeypot"
POSTGRES_DB = "honeypotdb"

LOCAL_SAMPLE_DIR = "malware_samples_storage"
YARA_RULES = "yara_rules/honeypot_basic_rules.yar"

REMOTE_DIRS = [
    "/tmp/enterprise-ftp-uploads",
    "/tmp/enterprise-ftp-root/uploads"
]

SUSPICIOUS_PATTERNS = [
    "wget ",
    "curl ",
    "chmod +x",
    "/bin/sh",
    "/bin/bash",
    "nc -e",
    "netcat",
    "/dev/tcp/",
    "base64 -d",
    "base64 --decode",
    "eval(",
    "system(",
    "shell_exec(",
    "passthru(",
    "powershell",
    "FromBase64String",
    "phpunit",
    "eval-stdin.php"
]


def run(cmd, timeout=60):
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout
    )


def sql_escape(value):
    if value is None:
        return ""
    return str(value).replace("'", "''")


def list_remote_files():
    files = []

    for remote_dir in REMOTE_DIRS:
        result = run([
            "docker", "exec", FTP_CONTAINER,
            "sh", "-c",
            f"test -d '{remote_dir}' && find '{remote_dir}' -type f -maxdepth 5 2>/dev/null || true"
        ])

        if result.stdout.strip():
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    files.append(line)

    return sorted(set(files))


def safe_name(remote_path):
    name = remote_path.strip("/").replace("/", "__")
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    return name[:180]


def copy_from_container(remote_path):
    os.makedirs(LOCAL_SAMPLE_DIR, exist_ok=True)

    local_path = os.path.join(LOCAL_SAMPLE_DIR, safe_name(remote_path))

    result = run([
        "docker", "cp",
        f"{FTP_CONTAINER}:{remote_path}",
        local_path
    ])

    if result.returncode != 0:
        print(f"[!] Failed to copy {remote_path}: {result.stderr.strip()}")
        return None

    try:
        os.chmod(local_path, 0o400)
    except Exception:
        pass

    return local_path


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)

    return h.hexdigest()


def find_suspicious_strings(path):
    matches = []

    try:
        with open(path, "rb") as f:
            data = f.read(1024 * 1024)

        text = data.decode("utf-8", errors="ignore").lower()

        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.lower() in text:
                matches.append(pattern)
    except Exception:
        pass

    return sorted(set(matches))


def run_yara(path):
    if not shutil.which("yara"):
        return []

    if not os.path.exists(YARA_RULES):
        return []

    result = run(["yara", YARA_RULES, path])

    matches = []
    if result.returncode in [0, 1]:
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if parts:
                matches.append(parts[0])

    return sorted(set(matches))


def derive_verdict(yara_matches, suspicious_strings, file_size):
    score = 0

    if yara_matches:
        score += 60

    if suspicious_strings:
        score += min(30, len(suspicious_strings) * 8)

    if file_size > 5 * 1024 * 1024:
        score += 10

    score = min(score, 100)

    if score >= 80:
        verdict = "Malicious/Suspicious"
    elif score >= 50:
        verdict = "Suspicious"
    elif score >= 20:
        verdict = "Needs Review"
    else:
        verdict = "Clean/Unknown"

    return score, verdict


def find_source_ip_for_upload(remote_path):
    # Best-effort: match the upload path to the latest FTP upload event.
    query = """
    SELECT COALESCE(source_ip, '')
    FROM events
    WHERE service = 'FTP'
      AND attack_type = 'File Upload Attempt'
    ORDER BY timestamp DESC
    LIMIT 1;
    """

    result = run([
        "docker", "exec", POSTGRES_CONTAINER,
        "psql", "-U", POSTGRES_USER, "-d", POSTGRES_DB,
        "-t", "-A", "-c", query
    ])

    if result.returncode == 0:
        return result.stdout.strip()

    return ""


def insert_sample(row):
    yara_array = "ARRAY[" + ",".join([f"'{sql_escape(x)}'" for x in row["yara_matches"]]) + "]"
    strings_array = "ARRAY[" + ",".join([f"'{sql_escape(x)}'" for x in row["suspicious_strings"]]) + "]"

    query = f"""
    INSERT INTO malware_samples (
        source_ip,
        service,
        original_path,
        local_path,
        file_name,
        file_size,
        sha256,
        yara_matches,
        suspicious_strings,
        risk_score,
        verdict,
        last_seen
    )
    VALUES (
        '{sql_escape(row["source_ip"])}',
        'FTP',
        '{sql_escape(row["original_path"])}',
        '{sql_escape(row["local_path"])}',
        '{sql_escape(row["file_name"])}',
        {row["file_size"]},
        '{sql_escape(row["sha256"])}',
        {yara_array},
        {strings_array},
        {row["risk_score"]},
        '{sql_escape(row["verdict"])}',
        CURRENT_TIMESTAMP
    )
    ON CONFLICT (sha256)
    DO UPDATE SET
        last_seen = CURRENT_TIMESTAMP,
        risk_score = EXCLUDED.risk_score,
        verdict = EXCLUDED.verdict,
        yara_matches = EXCLUDED.yara_matches,
        suspicious_strings = EXCLUDED.suspicious_strings;
    """

    result = run([
        "docker", "exec", "-i", POSTGRES_CONTAINER,
        "psql", "-U", POSTGRES_USER, "-d", POSTGRES_DB,
        "-c", query
    ])

    if result.returncode != 0:
        print("[!] DB insert failed:", result.stderr.strip())


def main():
    remote_files = list_remote_files()

    if not remote_files:
        print("No uploaded files found in FTP upload directories.")
        return

    print(f"Found {len(remote_files)} uploaded file(s).")

    for remote_path in remote_files:
        local_path = copy_from_container(remote_path)
        if not local_path:
            continue

        file_size = os.path.getsize(local_path)
        sha256 = sha256_file(local_path)
        yara_matches = run_yara(local_path)
        suspicious_strings = find_suspicious_strings(local_path)
        risk_score, verdict = derive_verdict(yara_matches, suspicious_strings, file_size)
        source_ip = find_source_ip_for_upload(remote_path)

        row = {
            "source_ip": source_ip,
            "original_path": remote_path,
            "local_path": os.path.abspath(local_path),
            "file_name": os.path.basename(remote_path),
            "file_size": file_size,
            "sha256": sha256,
            "yara_matches": yara_matches,
            "suspicious_strings": suspicious_strings,
            "risk_score": risk_score,
            "verdict": verdict
        }

        insert_sample(row)

        print(json.dumps(row, indent=2))


if __name__ == "__main__":
    main()
