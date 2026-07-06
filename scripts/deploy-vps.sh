#!/usr/bin/env bash
# Build + déploie sqli-hunter/tg-bot sur le VPS (sans lancer de scan).
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
  "$ROOT/sqli-hunter" "$ROOT/tg-bot" \
  "$ROOT/scripts/start-weekly.sh" \
  "$ROOT/scripts/start-monthly.sh" \
  "$ROOT/scripts/start-big.sh" \
  "$ROOT/scripts/stop-scans.sh" \
  "${TARGET}:/tmp/"

echo "→ install..." >&2
ssh -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -p "$VPS_PORT" -i "$KEY" "$TARGET" '
set -e
mv -f /tmp/sqli-hunter /tmp/tg-bot /opt/sqli-hunter/
for f in start-weekly.sh start-monthly.sh start-big.sh stop-scans.sh; do
  mv -f "/tmp/$f" /opt/sqli-hunter/ 2>/dev/null || true
done
chmod +x /opt/sqli-hunter/sqli-hunter /opt/sqli-hunter/tg-bot
chmod +x /opt/sqli-hunter/start-*.sh /opt/sqli-hunter/stop-scans.sh 2>/dev/null || true
export SQLI_HUNTER_ENV=/opt/sqli-hunter/sqli-hunter.env
export TG_BOT_ENV=/opt/sqli-hunter/tg-bot.env
systemctl restart sqli-tg-bot.service 2>/dev/null || true
/opt/sqli-hunter/sqli-hunter --version
'

echo "→ scan non lancé — ./start-weekly.sh ou ./start-monthly.sh sur le VPS" >&2
echo "✓ déployé" >&2
