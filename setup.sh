#!/usr/bin/env bash
set -euo pipefail

MODULE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$MODULE_DIR/module.conf" ]; then
  # shellcheck disable=SC1091
  source "$MODULE_DIR/module.conf"
fi

# shellcheck disable=SC1091
source "$MODULE_DIR/scripts/libabk.sh"

abk_require_env KERNEL_ROOT DEFCONFIG CUSTOM_EXTERNAL_MODULE_STAGE

abk_log "module: ${ABK_MODULE_NAME:-ABK FIDO Key}"
abk_log "version: ${ABK_MODULE_VERSION:-unknown}"
abk_log "stage: $CUSTOM_EXTERNAL_MODULE_STAGE"
abk_log "kernel root: $KERNEL_ROOT"
abk_log "kernel version: $(abk_kernel_version)"

abk_fido_python() {
  local interpreter
  for interpreter in python3 python; do
    # A resolvable name is not enough: some environments ship a stub that exits
    # without running anything, so require the interpreter to actually execute.
    if command -v "$interpreter" >/dev/null 2>&1 &&
      "$interpreter" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
        >/dev/null 2>&1; then
      printf '%s\n' "$interpreter"
      return 0
    fi
  done
  return 1
}

# Resolve once: abk_die inside a command substitution would only exit the
# subshell, so probe here where a failure can still stop the script.
PYTHON="$(abk_fido_python)" ||
  abk_die "a working python3 (>= 3.9) is required but was not found in PATH"

abk_fido_install() {
  "$PYTHON" "$MODULE_DIR/scripts/install.py" "$1" \
    --kernel-root "$KERNEL_ROOT" \
    --module-root "$MODULE_DIR" \
    --defconfig "$DEFCONFIG"
}

case "$CUSTOM_EXTERNAL_MODULE_STAGE" in
  after_patch)
    abk_fido_install install
    ;;
  before_build)
    # install is idempotent, so a single-stage ABK configuration still works.
    abk_fido_install install
    abk_fido_install enable-config
    abk_fido_install verify
    ;;
  *)
    abk_die "unsupported CUSTOM_EXTERNAL_MODULE_STAGE: $CUSTOM_EXTERNAL_MODULE_STAGE"
    ;;
esac

abk_log "done"
