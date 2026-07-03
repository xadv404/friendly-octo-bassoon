#!/usr/bin/env bash
# Exécute une commande sur le VPS (non-interactif, pour agents).
#
# Usage:
#   ./scripts/vps-run.sh 'cd /opt/sqli-hunter && ./sqli-hunter daily'
#   ./scripts/vps-run.sh -- ./sqli-hunter daily   # cwd = VPS_PATH
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/vps-env.sh
source "$ROOT/scripts/lib/vps-env.sh"
vps_require_vars

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <commande distante>" >&2
  echo "       $0 -- <cmd>   (exécuté dans VPS_PATH)" >&2
  exit 1
fi

mapfile -t SSH_ARGS < <(vps_ssh_base_args)
TARGET="$(vps_target)"

if [[ "${1:-}" == "--" ]]; then
  shift
  REMOTE_CMD="cd '${VPS_PATH}' && $*"
else
  REMOTE_CMD="$*"
fi

echo "→ run on ${TARGET}: ${REMOTE_CMD}" >&2
exec ssh "${SSH_ARGS[@]}" "$TARGET" "bash -lc $(printf '%q' "$REMOTE_CMD")"
