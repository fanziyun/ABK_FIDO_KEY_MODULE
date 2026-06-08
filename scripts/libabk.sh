#!/usr/bin/env bash

abk_log() {
  printf '[ABK FIDO] %s\n' "$*"
}

abk_warn() {
  printf '[ABK FIDO][warn] %s\n' "$*" >&2
}

abk_die() {
  printf '[ABK FIDO][error] %s\n' "$*" >&2
  exit 1
}

abk_require_env() {
  local name
  for name in "$@"; do
    if [ -z "${!name:-}" ]; then
      abk_die "required environment variable is empty: $name"
    fi
  done
}

abk_require_file() {
  local path="$1"
  [ -f "$path" ] || abk_die "required file not found: $path"
}

abk_require_dir() {
  local path="$1"
  [ -d "$path" ] || abk_die "required directory not found: $path"
}

abk_common_dir() {
  abk_require_env KERNEL_ROOT
  printf '%s/common\n' "$KERNEL_ROOT"
}

abk_append_line_once() {
  local file="$1"
  local line="$2"
  abk_require_file "$file"
  grep -qF "$line" "$file" || printf '%s\n' "$line" >> "$file"
}

abk_set_config() {
  local symbol="$1"
  local value="$2"
  local file="${3:-${DEFCONFIG:-}}"
  local clean_symbol tmp line

  [ -n "$file" ] || abk_die "DEFCONFIG is empty"
  abk_require_file "$file"

  clean_symbol="${symbol#CONFIG_}"
  tmp="$(mktemp)"

  grep -v -E "^(CONFIG_${clean_symbol}=|# CONFIG_${clean_symbol} is not set$)" "$file" > "$tmp" || true
  case "$value" in
    n) line="# CONFIG_${clean_symbol} is not set" ;;
    *) line="CONFIG_${clean_symbol}=${value}" ;;
  esac
  printf '%s\n' "$line" >> "$tmp"
  mv "$tmp" "$file"
}

abk_enable_config() {
  abk_set_config "$1" y "${2:-${DEFCONFIG:-}}"
}
