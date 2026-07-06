#!/usr/bin/env bash
# Lance une grosse passe (hebdo / bi-mensuel) — DBMS dorks + scan full/waf.
#
# Cron exemple (dimanche 2h) :
#   0 2 * * 0 cd /opt/sqli-hunter && ./sqli-hunter big >> results/big.log 2>&1
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
exec ./sqli-hunter big "$@"
