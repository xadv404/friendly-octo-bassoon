#!/usr/bin/env bash
# Connexion SSH interactive au VPS (agents / humains).
#
# Usage:
#   ./scripts/vps-ssh.sh
#   ./scripts/vps-ssh.sh -t                        # tmux sur le VPS
#   VPS_ENV=/path/vps.env ./scripts/vps-ssh.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/vps-env.sh
source "$ROOT/scripts/lib/vps-env.sh"

USE_TMUX=0
while getopts ":th" opt; do
  case "$opt" in
    t) USE_TMUX=1 ;;
    h)
      cat <<'EOF'
vps-ssh.sh — shell SSH sur le VPS configuré dans vps.env

  ./scripts/vps-ssh.sh       Ouvre bash dans VPS_PATH
  ./scripts/vps-ssh.sh -t    Idem + tmux attach/create "sqli"

Variables (vps.env): VPS_HOST, VPS_USER, VPS_PORT, VPS_PATH, SSH_KEY_PATH
EOF
      exit 0
      ;;
    *) echo "usage: $0 [-t]" >&2; exit 1 ;;
  esac
done

mapfile -t SSH_ARGS < <(vps_ssh_base_args)
TARGET="$(vps_target)"

REMOTE_CMD="cd '${VPS_PATH}' && exec bash -l"
if [[ "$USE_TMUX" -eq 1 ]]; then
  REMOTE_CMD="cd '${VPS_PATH}' && (tmux attach -t sqli 2>/dev/null || tmux new -s sqli)"
fi

echo "→ ssh ${TARGET}:${VPS_PATH}  (env: ${VPS_ENV_FILE:-vps.env})" >&2
exec ssh "${SSH_ARGS[@]}" "$TARGET" "$REMOTE_CMD"
