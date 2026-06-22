#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

docker compose exec -T api python soc_alert_notifier.py >> soc_alert_notifier.log 2>&1
