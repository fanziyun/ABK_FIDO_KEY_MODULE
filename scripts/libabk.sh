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
  if [ -f "$KERNEL_ROOT/common/Makefile" ]; then
    printf '%s/common\n' "$KERNEL_ROOT"
  elif [ -f "$KERNEL_ROOT/Makefile" ]; then
    printf '%s\n' "$KERNEL_ROOT"
  else
    abk_die "kernel Makefile not found below $KERNEL_ROOT"
  fi
}

abk_kernel_make_value() {
  local key="$1"
  local makefile
  makefile="$(abk_common_dir)/Makefile"
  abk_require_file "$makefile"
  awk -v key="$key" '$1 == key && $2 == "=" { print $3; exit }' "$makefile"
}

abk_kernel_version() {
  local version patchlevel sublevel
  version="$(abk_kernel_make_value VERSION)"
  patchlevel="$(abk_kernel_make_value PATCHLEVEL)"
  sublevel="$(abk_kernel_make_value SUBLEVEL)"
  printf '%s.%s.%s\n' "$version" "$patchlevel" "$sublevel"
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
  abk_log "set CONFIG_${clean_symbol}=$value in $file"
}

abk_enable_config() {
  abk_set_config "$1" y "${2:-${DEFCONFIG:-}}"
}
