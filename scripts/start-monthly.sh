#!/usr/bin/env bash
# Passe mensuelle — max absolu (80k URLs, 3000 pages, rescan total).
# Cron : 0 3 1 * * cd /opt/sqli-hunter && ./scripts/start-monthly.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
exec ./sqli-hunter monthly "$@"
