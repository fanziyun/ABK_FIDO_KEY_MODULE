#!/usr/bin/env bash
# Install the KernelSU module that lets the ABK FIDO driver's *kernel* domain
# (and the root shell the companion app runs) read and write the persisted
# store at /metadata/abk_fido_store.bin plus the driver's sysfs nodes.
#
# Why this is needed: the driver opens /metadata with a kernel domain credential
# (prepare_kernel_cred -> u:r:kernel:s0), and on enforcing SELinux that domain
# is denied metadata_file access, so every restore_metadata / persist fails with
#
#     restore_metadata rejected the store: ... Permission denied
#
# The compiled-in KernelSU rules.c path (patch_kernelsu_sepolicy_for_abk_fido.py)
# is unreliable across KernelSU builds, so ship the rule as a KernelSU module
# instead: `sepolicy.rule` is auto-applied every boot, and `post-fs-data.sh`
# re-patches as a fallback. Both run in enforce mode — this never switches SELinux
# to permissive.
#
# Usage:
#   ./scripts/install_abk_fido_selinux_module.sh            # install to the first adb device
#   ADB="adb -s <serial>" ./scripts/install_abk_fido_selinux_module.sh
set -e

ADB="${ADB:-adb}"

echo "==> creating /data/adb/modules/abk_fido_selinux"
"$ADB" shell 'su -c "mkdir -p /data/adb/modules/abk_fido_selinux"'

echo "==> writing module.prop"
cat <<'EOF' | "$ADB" shell 'su -c "cat > /data/adb/modules/abk_fido_selinux/module.prop"'
id=abk_fido_selinux
name=ABK FIDO SELinux rules
version=v1.0
versionCode=1
author=abk
description=Allow kernel domain to read/write the /metadata ABK FIDO store.
EOF

echo "==> writing sepolicy.rule (auto-applied at boot)"
cat <<'EOF' | "$ADB" shell 'su -c "cat > /data/adb/modules/abk_fido_selinux/sepolicy.rule"'
allow kernel metadata_file dir search
allow kernel metadata_file file { open read write getattr create }
EOF

echo "==> writing post-fs-data.sh (fallback re-patch)"
cat <<'EOF' | "$ADB" shell 'su -c "cat > /data/adb/modules/abk_fido_selinux/post-fs-data.sh"'
#!/system/bin/sh
# Reassert kernel-domain /metadata access every boot, in case sepolicy.rule is
# not applied by this KernelSU build. Runs as root.
KS=/data/adb/ksu/bin/ksud
$KS sepolicy patch "allow kernel metadata_file dir search" 2>/dev/null
$KS sepolicy patch "allow kernel metadata_file file { open read write getattr create }" 2>/dev/null
EOF

echo "==> setting permissions"
"$ADB" shell 'su -c "chmod 755 /data/adb/modules/abk_fido_selinux/post-fs-data.sh; chmod 644 /data/adb/modules/abk_fido_selinux/module.prop; chmod 644 /data/adb/modules/abk_fido_selinux/sepolicy.rule"'

echo "==> apply immediately for this session (no reboot needed for the current run)"
"$ADB" shell 'su -c "/data/adb/ksu/bin/ksud sepolicy patch \"allow kernel metadata_file dir search\" >/dev/null 2>&1; /data/adb/ksu/bin/ksud sepolicy patch \"allow kernel metadata_file file { open read write getattr create }\" >/dev/null 2>&1"'

echo "==> done. Verify the driver can now restore the store:"
echo "    adb shell su -c 'printf 1 > /sys/kernel/abk_fido_key/restore_metadata; echo err=\$(cat /sys/kernel/abk_fido_key/last_error); echo cnt=\$(cat /sys/kernel/abk_fido_key/credential_count)'"
echo "    expect empty err and the real credential count (not -13)."
echo "    Reboot for the rules to persist; the module survives (KernelSU module)."
