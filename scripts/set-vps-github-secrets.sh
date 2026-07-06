#!/usr/bin/env bash
# Enregistre la clé SSH VPS et la config dans les secrets GitHub Actions.
# Nécessite gh connecté avec droits admin sur le dépôt.
#
# Usage (depuis la racine du repo, après ssh-keygen) :
#   ./scripts/set-vps-github-secrets.sh
#   SSH_KEY_PATH=.ssh/vps_sqli_hunter ./scripts/set-vps-github-secrets.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEY="${SSH_KEY_PATH:-$ROOT/.ssh/vps_sqli_hunter}"
PUB="${KEY}.pub"

[[ -f "$KEY" ]] || { echo "clé introuvable: $KEY" >&2; exit 1; }
[[ -f "$PUB" ]] || { echo "clé publique introuvable: $PUB" >&2; exit 1; }

if ! gh auth status >/dev/null 2>&1; then
  echo "gh non authentifié — lance: gh auth login" >&2
  exit 1
fi

# shellcheck source=lib/vps-env.sh
source "$ROOT/scripts/lib/vps-env.sh"
vps_load_env 2>/dev/null || true

VPS_HOST="${VPS_HOST:-151.247.22.170}"
VPS_USER="${VPS_USER:-root}"
VPS_PORT="${VPS_PORT:-22}"
VPS_PATH="${VPS_PATH:-/opt/sqli-hunter}"

echo "→ secrets GitHub (repo $(gh repo view --json nameWithOwner -q .nameWithOwner))" >&2
gh secret set VPS_SSH_PRIVATE_KEY <"$KEY"
gh secret set VPS_SSH_PUBLIC_KEY <"$PUB"
gh secret set VPS_HOST --body "$VPS_HOST"
gh secret set VPS_USER --body "$VPS_USER"
gh secret set VPS_PORT --body "$VPS_PORT"
gh secret set VPS_PATH --body "$VPS_PATH"

echo "✓ secrets enregistrés" >&2
echo "" >&2
echo "Sur le VPS, ajoute la clé publique à authorized_keys :" >&2
cat "$PUB" >&2
