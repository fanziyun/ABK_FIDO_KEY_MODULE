#!/usr/bin/env bash

abk_fido_install_kernel_files() {
  local common_dir
  common_dir="$(abk_common_dir)"

  abk_require_dir "$common_dir/drivers"
  abk_require_dir "$common_dir/include/linux"
  abk_require_file "$common_dir/drivers/Kconfig"
  abk_require_file "$common_dir/drivers/Makefile"

  mkdir -p "$common_dir/drivers/abk_fido_key"
  cp -a "$MODULE_DIR/files/drivers/abk_fido_key/." "$common_dir/drivers/abk_fido_key/"
  cp -a "$MODULE_DIR/files/include/linux/abk_fido_key.h" "$common_dir/include/linux/abk_fido_key.h"

  abk_append_line_once "$common_dir/drivers/Kconfig" 'source "drivers/abk_fido_key/Kconfig"'
  abk_append_line_once "$common_dir/drivers/Makefile" 'obj-$(CONFIG_ABK_FIDO_KEY) += abk_fido_key/'
}

abk_fido_patch_usb_gadget() {
  local common_dir configfs
  common_dir="$(abk_common_dir)"
  configfs="$common_dir/drivers/usb/gadget/configfs.c"

  abk_require_file "$configfs"
  python3 "$MODULE_DIR/scripts/patch_configfs_for_abk_fido.py" "$configfs"
  # Fail the build if the FIDO interface injection is missing.
  grep -q "abk_fido_key_prepare_config" "$configfs" \
    || abk_die "ABK FIDO configfs patch missing the prepare_config injection"
  grep -q "abk_fido_key_release_config" "$configfs" \
    || abk_die "ABK FIDO configfs patch missing the release_config injection"
}

abk_fido_patch_kernelsu_sepolicy() {
  local common_dir rules
  common_dir="$(abk_common_dir)"
  rules="$common_dir/drivers/kernelsu/selinux/rules.c"

  # Skip cleanly when ABK builds without KernelSU.
  if [ ! -f "$rules" ]; then
    abk_warn "no KernelSU rules.c found; skipped the /metadata SELinux allow rules"
    abk_warn "persistence may be denied by SELinux"
    return 0
  fi

  python3 "$MODULE_DIR/scripts/patch_kernelsu_sepolicy_for_abk_fido.py" "$rules"
  grep -q "ABK FIDO: allow kernel domain access to the persisted metadata store." "$rules" \
    || abk_die "ABK FIDO KernelSU sepolicy patch missing metadata_file allow rules"
}

# The KernelSU SELinux module must ship with the kernel, not as a second flash:
# without it the driver's /metadata persist is denied and the app shows no keys.
# ABK clones AnyKernel3 before the external-module hooks run, so the module is
# injected into that tree and the AK3 zip built later picks it up. This keeps
# the fix inside this repository: no ABK workflow change is needed.
abk_fido_bundle_ksu_module_into_ak3() {
  local output
  if ! output="$(python3 "$MODULE_DIR/scripts/ak3_bundle_ksu_module.py" inject --ak3-dir auto 2>&1)"; then
    printf '%s\n' "$output" >&2
    abk_die "failed to bundle the KernelSU SELinux module into the AnyKernel3 tree"
  fi
  case "$output" in
    *"nothing to bundle"*)
      abk_warn "$output"
      abk_warn "the AK3 zip will not install the module; flash ksu/abk_fido_selinux manually"
      return 0
      ;;
  esac
  abk_log "$output"
  python3 "$MODULE_DIR/scripts/ak3_bundle_ksu_module.py" verify --ak3-dir auto >/dev/null \
    || abk_die "the AnyKernel3 tree does not carry a valid KernelSU module bundle"
}

abk_fido_enable_config() {
  abk_enable_config CONFIG_ABK_FIDO_KEY
  abk_enable_config CONFIG_ABK_FIDO_KEY_CTAP2
  abk_enable_config CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH
  abk_enable_config CONFIG_ABK_FIDO_KEY_PERSIST_METADATA
  abk_enable_config CONFIG_ABK_FIDO_KEY_PERSIST_ADB_DATA

  # Fail the build instead of shipping a phone that cannot enumerate the key.
  grep -q "^CONFIG_ABK_FIDO_KEY=y\$" "$DEFCONFIG" \
    || abk_die "CONFIG_ABK_FIDO_KEY missing from $DEFCONFIG"
  grep -q "^CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH=y\$" "$DEFCONFIG" \
    || abk_die "CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH missing from $DEFCONFIG"
}
