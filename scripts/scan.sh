#!/usr/bin/env bash
# Lance ou arrête les scans sqli-hunter sur le VPS.
#
# Usage:
#   ./scan.sh weekly|monthly   démarre en arrière-plan (log dans results/)
#   ./scan.sh stop             arrête les scans en cours
#   ./scan.sh status           liste les processus
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

cmd="${1:-}"
case "$cmd" in
  weekly|monthly|big)
    tier="$cmd"
    [[ "$tier" == "big" ]] && tier=weekly
    if pgrep -f "./sqli-hunter ${tier}" >/dev/null 2>&1; then
      echo "ALREADY_RUNNING ${tier}"
      exit 2
    fi
    mkdir -p results
    log="results/${tier}.log"
    nohup ./sqli-hunter "$tier" >>"$log" 2>&1 &
    echo "STARTED ${tier} pid=$! log=${log}"
    ;;
  stop)
    exec ./stop-scans.sh
    ;;
  status)
    pgrep -af './sqli-hunter' || echo "IDLE"
    ;;
  *)
    echo "usage: $0 weekly|monthly|stop|status" >&2
    exit 1
    ;;
esac
