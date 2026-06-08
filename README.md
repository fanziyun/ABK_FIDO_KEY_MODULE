# ABK FIDO Key Module

`abk_fido_key_module` is an ABK custom external kernel module that turns an
Android phone build into a composite USB FIDO2 security key.

`abk_fido_key_module` 是一个 ABK 自定义外部内核模块，用来把 Android
手机侧内核扩展成一个复合 USB FIDO2 Security Key。

Current version / 当前版本: `0.1.0`

## Overview / 项目概览

This module installs an out-of-tree kernel driver, patches the Android USB
gadget configfs flow, and auto-attaches an extra FIDO HID interface to the
active USB configuration.

这个模块会安装一个外部内核驱动，patch Android USB gadget 的 configfs
流程，并在当前激活的 USB 配置上自动追加一个 FIDO HID 接口。

What it adds / 它会增加这些内容:

- `common/drivers/abk_fido_key`
- `common/include/linux/abk_fido_key.h`
- `CONFIG_ABK_FIDO_KEY`
- `CONFIG_ABK_FIDO_KEY_CTAP2`
- `CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH`
- `CONFIG_ABK_FIDO_KEY_PERSIST_ADB_DATA`

## Repository Layout / 仓库结构

- `setup.sh`: external module entrypoint used by the ABK build hook.
- `module.conf`: module metadata, version, and supported stages.
- `scripts/`: helper shell and Python patch scripts.
- `files/drivers/abk_fido_key/`: kernel driver source, Kconfig, and Makefile.
- `files/include/linux/abk_fido_key.h`: public kernel header used by the
  configfs injection point.

## Integration / 接入方式

### Prerequisites / 前置条件

- An ABK or `new_test` style kernel build environment with `KERNEL_ROOT` and a
  `common/` kernel tree.
- `python3` available in the build environment.
- A `common/drivers/usb/gadget/configfs.c` layout compatible with the patch
  anchors used by `scripts/patch_configfs_for_abk_fido.py`.

### Generic Example / 通用示例

Add the module to `new_test/.local-build/env.sh`:

```bash
export USE_CUSTOM_EXTERNAL_MODULES="true"
export CUSTOM_EXTERNAL_MODULES="/abs/path/to/abk_fido_key_module;after_patch|/abs/path/to/abk_fido_key_module;before_build"
```

### Repository URL Example / 仓库 URL 示例

If your ABK external-module loader supports Git URLs directly, you can also use
the public repository address:

如果你的 ABK 外部模块加载器支持直接拉取 Git URL，也可以直接使用公开仓库地址：

```bash
export USE_CUSTOM_EXTERNAL_MODULES="true"
export CUSTOM_EXTERNAL_MODULES="https://github.com/xingguangcuican6666/ABK_FIDO_KEY_MODULE.git;after_patch|https://github.com/xingguangcuican6666/ABK_FIDO_KEY_MODULE.git;before_build"
```

### Local Example / 当前本地示例

```bash
export USE_CUSTOM_EXTERNAL_MODULES="true"
export CUSTOM_EXTERNAL_MODULES="/run/media/xingguangcuican/Project/kernelexp/new_test/abk_fido_key_module;after_patch|/run/media/xingguangcuican/Project/kernelexp/new_test/abk_fido_key_module;before_build"
```

Then rebuild:

```bash
./rebuild.sh --reseed
```

## Stage Behavior / 阶段行为

- `after_patch`: install kernel files and patch
  `common/drivers/usb/gadget/configfs.c`.
- `before_build`: do everything from `after_patch`, then enable the required
  `CONFIG_ABK_FIDO_KEY*` symbols in `DEFCONFIG`.

The patch injects `abk_fido_key_prepare_config()` into the gadget config bind
flow so the `abk_fido` function is added automatically when the USB gadget is
assembled.

这个 patch 会把 `abk_fido_key_prepare_config()` 注入 gadget config bind
流程，在组装 USB gadget 时自动添加 `abk_fido` function。

## Runtime Behavior / 运行期行为

- Adds one extra FIDO HID interface on top of the existing Android composite
  gadget.
- Exposes a misc debug node as `/dev/hidgX` where `X` is usually `0` to `3`.
- Exposes read-only status nodes under `/sys/kernel/abk_fido_key/`:
  `enabled`, `bound`, `udc`, `hid_dev`, `credential_count`, `last_error`.
- Supports CTAP HID `INIT`, `PING`, `WINK`, `CBOR`, and `CANCEL`.
- Implements CTAP2 `getInfo`, `makeCredential`, `getAssertion`, `clientPIN`
  (minimal), `reset`, and `selection`.

## Validation / 验证方式

After a successful build and boot, check:

- the driver files were copied into `common/drivers/abk_fido_key`
- `CONFIG_ABK_FIDO_KEY=y` and related symbols are enabled
- `/sys/kernel/abk_fido_key/hid_dev` reports a `hidgX` device name
- `/sys/kernel/abk_fido_key/bound` becomes `1` after the gadget is bound
- `/dev/hidgX` exists for packet-level debugging

## Metadata / 元数据

Public module metadata lives in `module.conf` and is intended to match the
published repository.

公开模块元数据位于 `module.conf`，并且应与发布后的仓库保持一致。

## Current Limits / 当前边界

- This is a first-pass kernel-side CTAP2 implementation aimed at
  registration/authentication flows.
- The module identifies itself as a generic `Security Key`; it does not try to
  emulate a YubiKey.
- `clientPIN` is intentionally minimal and does not cover full advanced
  credential-management extensions.
- The store path constant is currently `/data/adb/abk_fido_store.bin`.
  Existing data can be loaded from that path, but write-back persistence is not
  finished yet: `abk_fido_maybe_persist_locked()` is still a stub.
- The configfs patcher depends on specific anchors in
  `common/drivers/usb/gadget/configfs.c`; if the kernel tree diverges, the
  patch step must be updated.
