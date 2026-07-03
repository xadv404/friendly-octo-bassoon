#!/usr/bin/env bash
# Démarre tg-bot (systemd) + daily sur le VPS.
set -euo pipefail
cd /opt/sqli-hunter
export SQLI_HUNTER_ENV=/opt/sqli-hunter/sqli-hunter.env
export TG_BOT_ENV=/opt/sqli-hunter/tg-bot.env

pkill -f "/opt/sqli-hunter/sqli-hunter daily" 2>/dev/null || true
sleep 1

systemctl restart sqli-tg-bot.service
sleep 2

nohup ./sqli-hunter daily >> results/daily.log 2>&1 &
sleep 2
pgrep -af "/opt/sqli-hunter/tg-bot"
pgrep -af "sqli-hunter daily"
