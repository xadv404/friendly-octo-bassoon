#!/usr/bin/env bash
# Build + déploie sqli-hunter/tg-bot sur le VPS et relance le daily.
#
# Prérequis: vps.env (VPS_HOST, VPS_USER, SSH_KEY_PATH, VPS_PATH)
#
# Usage:
#   ./scripts/deploy-vps.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/vps-env.sh
source "$ROOT/scripts/lib/vps-env.sh"
vps_require_vars

mapfile -t SSH_ARGS < <(vps_ssh_base_args)
TARGET="$(vps_target)"
KEY="${SSH_KEY_PATH/#\~/$HOME}"

echo "→ build..." >&2
(cd "$ROOT" && go build -o sqli-hunter ./cmd/sqli-hunter && go build -o tg-bot ./cmd/tg-bot)

echo "→ upload..." >&2
scp -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -P "$VPS_PORT" -i "$KEY" \
  "$ROOT/sqli-hunter" "$ROOT/tg-bot" "$ROOT/scripts/start-daily.sh" \
  "${TARGET}:/tmp/"

echo "→ install + daily..." >&2
ssh -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -p "$VPS_PORT" -i "$KEY" "$TARGET" '
set -e
mv -f /tmp/sqli-hunter /tmp/tg-bot /opt/sqli-hunter/
mv -f /tmp/start-daily.sh /opt/sqli-hunter/
chmod +x /opt/sqli-hunter/sqli-hunter /opt/sqli-hunter/tg-bot /opt/sqli-hunter/start-daily.sh
/opt/sqli-hunter/start-daily.sh
sleep 3
tail -15 /opt/sqli-hunter/results/daily.log 2>/dev/null || true
cat /opt/sqli-hunter/results/run_status.json 2>/dev/null || true
'

echo "✓ déployé et daily lancé" >&2
