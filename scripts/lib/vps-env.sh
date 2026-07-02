#!/usr/bin/env bash
# Charge vps.env — partagé par scripts/vps-*.sh
set -euo pipefail

VPS_ENV_LOADED=0

vps_repo_root() {
  local root
  root="$(cd "$(dirname "${BASH_SOURCE[1]}")/.." && pwd)"
  echo "$root"
}

vps_load_dotenv() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  set -a
  # shellcheck disable=SC1090
  source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$path" | grep -v '^#' || true)
  set +a
  return 0
}

vps_load_env() {
  [[ "${VPS_ENV_LOADED:-0}" -eq 1 ]] && return 0

  local root candidates path
  root="$(vps_repo_root)"
  candidates=(
    "${VPS_ENV:-}"
    "$root/vps.env"
    "$root/config/vps.env"
    "$HOME/.config/sqli-hunter/vps.env"
  )

  for path in "${candidates[@]}"; do
    [[ -z "$path" ]] && continue
    if vps_load_dotenv "$path"; then
      VPS_ENV_LOADED=1
      VPS_ENV_FILE="$path"
      export VPS_ENV_FILE
      return 0
    fi
  done

  echo "erreur: vps.env introuvable. Copie vps.env.example → vps.env" >&2
  return 1
}

vps_require_vars() {
  vps_load_env
  local missing=()
  [[ -z "${VPS_HOST:-}" ]] && missing+=("VPS_HOST")
  [[ -z "${VPS_USER:-}" ]] && missing+=("VPS_USER")
  [[ -z "${VPS_PATH:-}" ]] && missing+=("VPS_PATH")
  if ((${#missing[@]})); then
    echo "erreur: variables manquantes dans vps.env: ${missing[*]}" >&2
    return 1
  fi
  VPS_PORT="${VPS_PORT:-22}"
  SSH_CONNECT_TIMEOUT="${SSH_CONNECT_TIMEOUT:-15}"
  export VPS_HOST VPS_USER VPS_PORT VPS_PATH SSH_CONNECT_TIMEOUT
}

vps_ssh_base_args() {
  vps_require_vars
  local -a args=(
    -o "ConnectTimeout=${SSH_CONNECT_TIMEOUT}"
    -o BatchMode=yes
    -p "$VPS_PORT"
  )

  if [[ -n "${SSH_OPTIONS:-}" ]]; then
    # shellcheck disable=SC2206
    local extra=($SSH_OPTIONS)
    args+=("${extra[@]}")
  fi

  if [[ -n "${SSH_KEY_PATH:-}" ]]; then
    local key="${SSH_KEY_PATH/#\~/$HOME}"
    if [[ ! -f "$key" ]]; then
      echo "erreur: clé SSH introuvable: $key" >&2
      return 1
    fi
    chmod 600 "$key" 2>/dev/null || true
    args+=(-i "$key")
  fi

  if [[ -n "${VPS_JUMP_HOST:-}" ]]; then
    local jump_user="${VPS_JUMP_USER:-$VPS_USER}"
    args+=(-J "${jump_user}@${VPS_JUMP_HOST}")
  fi

  printf '%s\n' "${args[@]}"
}

vps_target() {
  vps_require_vars
  echo "${VPS_USER}@${VPS_HOST}"
}
