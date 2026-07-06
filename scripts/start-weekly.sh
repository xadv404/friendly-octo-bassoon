#!/usr/bin/env bash
# Passe hebdo — max vulns + emails (40k URLs, rescan, full+waf).
# Cron : 0 2 * * 0 cd /opt/sqli-hunter && ./scripts/start-weekly.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
exec ./sqli-hunter weekly "$@"
