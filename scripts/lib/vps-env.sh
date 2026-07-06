#!/usr/bin/env bash
# Charge vps.env — partagé par scripts/vps-*.sh
set -euo pipefail

VPS_ENV_LOADED=0

vps_repo_root() {
  local dir
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # scripts/lib → repo root
  if [[ "$(basename "$(dirname "$dir")")" == "scripts" ]]; then
    echo "$(cd "$dir/../.." && pwd)"
    return
  fi
  echo "$(cd "$dir/.." && pwd)"
}

vps_load_dotenv() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    [[ "$line" != *=* ]] && continue
    local key="${line%%=*}"
    local val="${line#*=}"
    key="$(echo "$key" | sed 's/[[:space:]]*$//')"
    val="$(echo "$val" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/^"//;s/"$//;s/^'"'"'//;s/'"'"'$//')"
    [[ -n "$key" ]] && export "$key=$val"
  done < "$path"
  return 0
}

vps_materialize_ssh_key() {
  [[ -n "${VPS_SSH_PRIVATE_KEY:-}" ]] || return 0
  local key="${SSH_KEY_PATH:-}"
  if [[ -z "$key" ]]; then
    key="${TMPDIR:-/tmp}/sqli-hunter-vps-ssh-$$"
    SSH_KEY_PATH="$key"
    export SSH_KEY_PATH
  else
    key="${key/#\~/$HOME}"
    SSH_KEY_PATH="$key"
    export SSH_KEY_PATH
  fi
  if [[ ! -f "$key" ]]; then
    printf '%s\n' "$VPS_SSH_PRIVATE_KEY" >"$key"
    chmod 600 "$key"
  fi
}

vps_load_env() {
  [[ "${VPS_ENV_LOADED:-0}" -eq 1 ]] && return 0

  if [[ -n "${VPS_HOST:-}" && -n "${VPS_USER:-}" && -n "${VPS_PATH:-}" ]]; then
    VPS_ENV_LOADED=1
    VPS_ENV_FILE="${VPS_ENV_FILE:-<env>}"
    export VPS_ENV_FILE
    vps_materialize_ssh_key
    return 0
  fi

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
      vps_materialize_ssh_key
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
