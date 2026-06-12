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
}

abk_fido_enable_config() {
  abk_enable_config CONFIG_ABK_FIDO_KEY
  abk_enable_config CONFIG_ABK_FIDO_KEY_CTAP2
  abk_enable_config CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH
  abk_enable_config CONFIG_ABK_FIDO_KEY_PERSIST_METADATA
  abk_enable_config CONFIG_ABK_FIDO_KEY_PERSIST_ADB_DATA
}
