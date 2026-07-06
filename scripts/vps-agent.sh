#!/usr/bin/env bash
# Point d'entrée agent : vérifie la connexion VPS et affiche le contexte.
#
# Usage (autres agents / environnements):
#   ./scripts/vps-agent.sh check
#   ./scripts/vps-agent.sh info
#   ./scripts/vps-agent.sh daily
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/vps-env.sh
source "$ROOT/scripts/lib/vps-env.sh"

CMD="${1:-check}"
shift || true

case "$CMD" in
  check)
    vps_require_vars
    mapfile -t SSH_ARGS < <(vps_ssh_base_args)
    TARGET="$(vps_target)"
    echo "env:     ${VPS_ENV_FILE:-vps.env}"
    echo "target:  ${TARGET}"
    echo "path:    ${VPS_PATH}"
  ssh "${SSH_ARGS[@]}" "$TARGET" "echo 'OK — connected as' \$(whoami)@\$(hostname) && test -d '${VPS_PATH}' && echo 'OK — path exists: ${VPS_PATH}'"
    ;;
  info)
    "$ROOT/scripts/vps-run.sh" -- 'pwd && ls -la && test -f sqli-hunter && ./sqli-hunter -h | head -3'
    ;;
  ssh)
    exec "$ROOT/scripts/vps-ssh.sh" "$@"
    ;;
  run)
    exec "$ROOT/scripts/vps-run.sh" "$@"
    ;;
  sync)
    exec "$ROOT/scripts/vps-sync.sh" "$@"
    ;;
  weekly)
    exec "$ROOT/scripts/vps-run.sh" -- './start-weekly.sh'
    ;;
  monthly)
    exec "$ROOT/scripts/vps-run.sh" -- './start-monthly.sh'
    ;;
  bot)
    exec "$ROOT/scripts/vps-run.sh" -- 'nohup ./tg-bot >> results/tg-bot.log 2>&1 & sleep 1 && tail -3 results/tg-bot.log'
    ;;
  *)
    cat <<'EOF'
vps-agent.sh — outils VPS pour agents Cursor / CI

  check     Teste SSH + VPS_PATH
  info      ls + version sqli-hunter distant
  ssh       Shell interactif (vps-ssh.sh)
  run CMD   Commande distante (vps-run.sh)
  sync      Build + rsync binaires/env
  weekly    Lance ./start-weekly.sh sur le VPS
  monthly   Lance ./start-monthly.sh sur le VPS
  bot       Démarre tg-bot en arrière-plan

Prérequis: vps.env (voir vps.env.example) + clé SSH
EOF
    exit 1
    ;;
esac
