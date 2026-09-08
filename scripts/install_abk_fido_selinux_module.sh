#!/usr/bin/env bash
# Install the KernelSU module that lets the ABK FIDO driver's *kernel* domain
# read and write the persisted store at /metadata/abk_fido_store.bin.
#
# Why this is needed: the driver opens the blob with a kernel-domain credential
# (prepare_kernel_cred -> u:r:kernel:s0), and on an enforcing device that domain
# is denied metadata_file access, so every persist and restore fails with -13:
#
#     persist deferred (will retry): persist open /metadata/abk_fido_store.bin failed: -13
#
# The file then stays 0 bytes and the companion app's "Registered FIDO keys"
# list stays empty even though the credential is live in the driver. The rules
# live in ksu/abk_fido_selinux/sepolicy.rule, are applied by KernelSU every
# boot, and post-fs-data.sh re-applies them as a fallback. SELinux stays
# enforcing — this never switches to permissive.
#
# Usage:
#   ./scripts/install_abk_fido_selinux_module.sh            # first adb device
#   ADB="adb -s <serial>" ./scripts/install_abk_fido_selinux_module.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE_ID=abk_fido_selinux
ZIP="$REPO_DIR/build/ksu/$MODULE_ID.zip"
RULE_SRC="$REPO_DIR/ksu/$MODULE_ID/sepolicy.rule"
REMOTE_ZIP=/data/local/tmp/$MODULE_ID.zip
REMOTE_RULE=/data/local/tmp/$MODULE_ID.sepolicy.rule

# Git Bash and MSYS rewrite /data/... into a Windows path, which breaks every
# adb argument that is a device path. Both variables are no-ops elsewhere, and
# the native tools below get an explicit Windows spelling instead.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

read -r -a ADB_CMD <<<"${ADB:-adb}"

if command -v cygpath >/dev/null 2>&1; then
  PYTHON_REPO_DIR="$(cygpath -w "$REPO_DIR")"
  PUSH_ZIP="$(cygpath -w "$ZIP")"
  PUSH_RULE="$(cygpath -w "$RULE_SRC")"
else
  PYTHON_REPO_DIR="$REPO_DIR"
  PUSH_ZIP="$ZIP"
  PUSH_RULE="$RULE_SRC"
fi

echo "==> packaging ksu/$MODULE_ID"
python3 "$PYTHON_REPO_DIR/scripts/build_ksu_module.py"

echo "==> pushing the module and its rules"
"${ADB_CMD[@]}" push "$PUSH_ZIP" "$REMOTE_ZIP"
"${ADB_CMD[@]}" push "$PUSH_RULE" "$REMOTE_RULE"

echo "==> installing with ksud module install"
"${ADB_CMD[@]}" shell "su -c 'ksud module install $REMOTE_ZIP'"

echo "==> applying the rules to the running policy (no reboot needed)"
# ksud installs into /data/adb/modules_update until the next boot, so the rules
# are applied from the pushed copy rather than from the module directory.
"${ADB_CMD[@]}" shell "su -c 'ksud sepolicy apply $REMOTE_RULE'"

echo "==> done. The rules survive a reboot; verify with:"
echo "    adb shell su -c 'cat /sys/kernel/abk_fido_key/last_trace'"
echo "    adb shell 'dmesg | grep \"avc.*metadata_file\" | tail -5'   # no new denials"
echo "    adb shell su -c 'printf 1 > /sys/kernel/abk_fido_key/restore_metadata'"
echo "    adb shell su -c 'cat /sys/kernel/abk_fido_key/last_trace'   # ... via restore_metadata"
echo "    expect an empty last_error and a real credential count, not -13."
echo "    The companion app must be 0.4.0 (versionCode 2) or newer: 0.2.0 cannot"
echo "    parse the version 2 store blob and has no /sys store_blob fallback."
