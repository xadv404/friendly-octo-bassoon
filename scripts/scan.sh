#!/usr/bin/env bash
# Lance ou arrête les scans sqli-hunter sur le VPS.
#
# Usage:
#   ./scan.sh [hunt]           démarre hunt en arrière-plan (défaut)
#   ./scan.sh stop
#   ./scan.sh status
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

hunt_running() {
  pgrep -f 'sqli-hunter hunt' >/dev/null 2>&1
}

cmd="${1:-hunt}"
shift || true

case "$cmd" in
  hunt|weekly|monthly|big)
    [[ "$cmd" == "weekly" || "$cmd" == "monthly" || "$cmd" == "big" ]] && cmd=hunt
    if hunt_running; then
      echo "ALREADY_RUNNING hunt"
      exit 2
    fi
    mkdir -p results
    log="results/hunt.log"
    export TG_BOT_ENV="${ROOT}/tg-bot.env"
    export SQLI_HUNTER_ENV="${ROOT}/sqli-hunter.env"
    nohup ./sqli-hunter hunt "$@" >>"$log" 2>&1 &
    echo "STARTED hunt pid=$! log=${log}"
    ;;
  stop)
    exec ./stop-scans.sh
    ;;
  status)
    pgrep -af 'sqli-hunter hunt' || echo "IDLE"
    ;;
  *)
    echo "usage: $0 [hunt] | stop | status" >&2
    exit 1
    ;;
esac
