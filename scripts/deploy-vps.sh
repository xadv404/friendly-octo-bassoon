#!/usr/bin/env bash
# Build + déploie sqli-hunter/tg-bot sur le VPS (sans lancer de scan).
#
# Prérequis: vps.env (VPS_HOST, VPS_USER, SSH_KEY_PATH, VPS_PATH)
#
# Usage:
#   ./scripts/deploy-vps.sh                 # install binaires + tg-bot seulement
#   ./scripts/deploy-vps.sh --start-daily   # install + lance daily (explicite)
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/vps-env.sh
source "$ROOT/scripts/lib/vps-env.sh"
vps_require_vars

START_DAILY=0
for arg in "$@"; do
	case "$arg" in
	--start-daily) START_DAILY=1 ;;
	esac
done

mapfile -t SSH_ARGS < <(vps_ssh_base_args)
TARGET="$(vps_target)"
KEY="${SSH_KEY_PATH/#\~/$HOME}"

echo "→ build..." >&2
(cd "$ROOT" && go build -o sqli-hunter ./cmd/sqli-hunter && go build -o tg-bot ./cmd/tg-bot)

echo "→ upload..." >&2
scp -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -P "$VPS_PORT" -i "$KEY" \
  "$ROOT/sqli-hunter" "$ROOT/tg-bot" \
  "$ROOT/scripts/start-daily.sh" \
  "$ROOT/scripts/start-weekly.sh" \
  "$ROOT/scripts/start-monthly.sh" \
  "$ROOT/scripts/start-big.sh" \
  "${TARGET}:/tmp/"

echo "→ install..." >&2
ssh -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -p "$VPS_PORT" -i "$KEY" "$TARGET" '
set -e
mv -f /tmp/sqli-hunter /tmp/tg-bot /opt/sqli-hunter/
for f in start-daily.sh start-weekly.sh start-monthly.sh start-big.sh; do
  mv -f "/tmp/$f" /opt/sqli-hunter/ 2>/dev/null || true
done
chmod +x /opt/sqli-hunter/sqli-hunter /opt/sqli-hunter/tg-bot
chmod +x /opt/sqli-hunter/start-*.sh 2>/dev/null || true
export SQLI_HUNTER_ENV=/opt/sqli-hunter/sqli-hunter.env
export TG_BOT_ENV=/opt/sqli-hunter/tg-bot.env
systemctl restart sqli-tg-bot.service 2>/dev/null || true
pgrep -af /opt/sqli-hunter/tg-bot || true
/opt/sqli-hunter/sqli-hunter --version
'

if [[ "$START_DAILY" -eq 1 ]]; then
	echo "→ start daily (demandé)..." >&2
	ssh -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
		-p "$VPS_PORT" -i "$KEY" "$TARGET" '/opt/sqli-hunter/start-daily.sh'
else
	echo "→ scan non lancé — lance manuellement: start-daily.sh | start-weekly.sh | start-monthly.sh" >&2
fi

echo "✓ déployé" >&2
