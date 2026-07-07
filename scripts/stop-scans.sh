#!/usr/bin/env bash
# Arrête les scans sqli-hunter en cours (hunt/ch).
# Ne touche pas au tg-bot.
set -euo pipefail
cd /opt/sqli-hunter
pkill -f 'sqli-hunter hunt' 2>/dev/null || true
pkill -f 'sqli-hunter weekly' 2>/dev/null || true
pkill -f 'sqli-hunter monthly' 2>/dev/null || true
pkill -f 'sqli-hunter big' 2>/dev/null || true
pkill -f 'sqli-hunter ch' 2>/dev/null || true
sleep 1
echo "scans arrêtés:"
pgrep -af 'sqli-hunter hunt' || echo "(aucun)"
