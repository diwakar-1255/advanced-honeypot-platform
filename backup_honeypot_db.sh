#!/bin/bash
set -e

BACKUP_DIR="/home/diwakar_1255/honeypot_backups"
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
FILE="$BACKUP_DIR/honeypotdb_$DATE.sql.gz"

mkdir -p "$BACKUP_DIR"

docker exec honeypot-postgres pg_dump -U honeypot honeypotdb | gzip > "$FILE"

find "$BACKUP_DIR" -type f -name "honeypotdb_*.sql.gz" -mtime +7 -delete

echo "Backup created: $FILE"
