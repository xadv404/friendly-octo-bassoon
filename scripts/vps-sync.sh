#!/usr/bin/env bash
# Build local + sync binaires et fichiers env vers le VPS.
#
# Usage:
#   ./scripts/vps-sync.sh
#   ./scripts/vps-sync.sh --daily   # lance daily après sync
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/vps-env.sh
source "$ROOT/scripts/lib/vps-env.sh"

RUN_DAILY=0
for arg in "$@"; do
  [[ "$arg" == "--daily" ]] && RUN_DAILY=1
done

vps_require_vars
mapfile -t SSH_ARGS < <(vps_ssh_base_args)
TARGET="$(vps_target)"
RSYNC_SSH="ssh ${SSH_ARGS[*]}"

echo "→ build local..." >&2
(cd "$ROOT" && go build -o sqli-hunter ./cmd/sqli-hunter && go build -o tg-bot ./cmd/tg-bot)

echo "→ mkdir ${VPS_PATH} on VPS..." >&2
ssh "${SSH_ARGS[@]}" "$TARGET" "mkdir -p '${VPS_PATH}/results'"

echo "→ rsync binaires..." >&2
rsync -avz -e "$RSYNC_SSH" \
  "$ROOT/sqli-hunter" \
  "$ROOT/tg-bot" \
  "${TARGET}:${VPS_PATH}/"

for envfile in sqli-hunter.env tg-bot.env; do
  if [[ -f "$ROOT/$envfile" ]]; then
    echo "→ rsync $envfile..." >&2
    rsync -avz -e "$RSYNC_SSH" "$ROOT/$envfile" "${TARGET}:${VPS_PATH}/"
  else
    echo "⚠ skip $envfile (absent localement)" >&2
  fi
done

if [[ -f "$ROOT/vps.env" ]]; then
  echo "→ vps.env reste local (non synchronisé)" >&2
fi

echo "✓ sync terminé → ${TARGET}:${VPS_PATH}" >&2

if [[ "$RUN_DAILY" -eq 1 ]]; then
  echo "→ lancement daily distant..." >&2
  ssh "${SSH_ARGS[@]}" "$TARGET" "cd '${VPS_PATH}' && ./sqli-hunter daily"
fi
