#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

docker compose exec -T api python soc_alert_engine.py >> soc_alert_engine.log 2>&1
