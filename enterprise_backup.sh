#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

BACKUP_ROOT="honeypot_backups"
TS="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/backup_$TS"

mkdir -p "$BACKUP_DIR"

echo "[+] Creating backup folder: $BACKUP_DIR"

echo "[+] Backing up PostgreSQL database..."
docker exec honeypot-postgres pg_dump -U honeypot honeypotdb | gzip > "$BACKUP_DIR/honeypotdb_$TS.sql.gz"

echo "[+] Backing up Grafana dashboard..."
set -a
source .env
set +a

if [ -z "${GRAFANA_ADMIN_PASSWORD:-}" ]; then
  echo "[-] GRAFANA_ADMIN_PASSWORD is not set in .env"
  exit 1
fi

curl -s \
  -u "admin:${GRAFANA_ADMIN_PASSWORD}" \
  "http://localhost:3000/api/dashboards/uid/advanced-honeypot-soc" \
  -o "$BACKUP_DIR/grafana_dashboard_$TS.json"

echo "[+] Backing up safe config files..."
cp docker-compose.yml "$BACKUP_DIR/docker-compose.yml"
cp docker-compose.override.yml "$BACKUP_DIR/docker-compose.override.yml" 2>/dev/null || true
cp .env.example "$BACKUP_DIR/.env.example"
cp README.md "$BACKUP_DIR/README.md" 2>/dev/null || true

echo "[+] Creating checksum file..."
cd "$BACKUP_DIR"
sha256sum * > SHA256SUMS.txt
cd - >/dev/null

echo "[+] Backup completed successfully:"
echo "$BACKUP_DIR"
