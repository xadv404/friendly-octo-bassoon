#!/usr/bin/env bash
# Passe hunt — scan scope_hunt.txt (.ch), dorks manuels.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
exec ./sqli-hunter hunt "$@"
