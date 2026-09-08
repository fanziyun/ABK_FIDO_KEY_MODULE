#!/system/bin/sh
# Reassert the kernel-domain /metadata rules every boot, in case this KernelSU
# build does not auto-apply sepolicy.rule, and pre-create the store file so the
# driver's common path is file open/write only. Never switches SELinux
# permissive: the rules are additive and the policy stays enforcing.
MODDIR=${0%/*}
KS=/data/adb/ksud
[ -x "$KS" ] || KS=/data/adb/ksu/bin/ksud
STORE=/metadata/abk_fido_store.bin

if [ -x "$KS" ] && [ -f "$MODDIR/sepolicy.rule" ]; then
  # Idempotent: re-applying rules that sepolicy.rule already loaded is a no-op,
  # and a rejected duplicate must not abort the boot stage.
  "$KS" sepolicy apply "$MODDIR/sepolicy.rule" >/dev/null 2>&1 || true
fi

if [ ! -e "$STORE" ]; then
  : > "$STORE" 2>/dev/null || true
fi

if [ -e "$STORE" ]; then
  chown root:root "$STORE" 2>/dev/null || true
  chmod 0600 "$STORE" 2>/dev/null || true
  restorecon "$STORE" 2>/dev/null || true
fi
