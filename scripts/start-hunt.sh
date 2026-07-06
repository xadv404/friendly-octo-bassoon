#!/usr/bin/env bash
# Passe hunt — discover + scan (.ch), lancement manuel.
# Cycle 1–4 semaines : HUNT_CYCLE_WEEKS dans sqli-hunter.env ou --cycle-weeks N
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
exec ./sqli-hunter hunt "$@"
