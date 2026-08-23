# ABK FIDO Key Module

`abk_fido_key_module` is an ABK custom external kernel module that turns an
Android phone build into a composite USB FIDO2 security key.

`abk_fido_key_module` 是一个 ABK 自定义外部内核模块，用来把 Android
手机侧内核扩展成一个复合 USB FIDO2 Security Key。

Current version / 当前版本: `0.3.0`

Supported kernel lines / 支持的内核线: **5.15** (`android13-5.15-lts`) and
**6.1** (`android14-6.1-lts`). The installer reads `common/Makefile` and refuses
any other line rather than producing a tree that fails deep in the kernel build.

安装器会读取 `common/Makefile` 判断内核线，只接受 5.15 与 6.1；其它内核线直接
报错退出，不会留下一个到编译后期才失败的内核树。

The one kernel-API difference between these lines that affects this driver is the
internal ECC header: 5.15 keeps it at `crypto/ecc.h` (outside `include/`, so only
reachable by relative path), while 5.16 and later expose
`<crypto/internal/ecc.h>`. `core.c` selects the right one with `__has_include`,
so a single source tree builds on both lines. Every other kernel API this driver
uses is signature-identical across 5.15.178 and 6.1.118.

两条内核线之间唯一影响本驱动的 API 差异是内部 ECC 头文件位置：5.15 在
`crypto/ecc.h`（不在 `include/` 下，只能相对路径引用），5.16 起改为
`<crypto/internal/ecc.h>`。`core.c` 用 `__has_include` 自动选择，因此同一份
源码在两条线上都能编译。其余用到的内核 API 在 5.15.178 与 6.1.118 上签名一致。

The gadget function is declared with `DECLARE_USB_FUNCTION` and registered from
the driver's own `abk_fido_core_init()`. `DECLARE_USB_FUNCTION_INIT` would expand
to a second `module_init`/`module_exit` pair and collide with that one, so
`verify` requires the plain macro and rejects the `_INIT` form. This is identical
on both kernel lines.

gadget function 用 `DECLARE_USB_FUNCTION` 声明，并在驱动自己的
`abk_fido_core_init()` 里注册。`DECLARE_USB_FUNCTION_INIT` 会额外展开出一对
`module_init`/`module_exit`，与已有的冲突，因此 `verify` 只接受不带 `_INIT`
的宏，遇到 `_INIT` 形式直接报错。两条内核线上行为一致。

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
- `CONFIG_ABK_FIDO_KEY_PERSIST_METADATA`
- `CONFIG_ABK_FIDO_KEY_PERSIST_ADB_DATA` (compatibility toggle)
- `app/`: optional Android companion that mirrors the kernel store blob into a
  SQLite database persisted on `/metadata`

## Repository Layout / 仓库结构

- `setup.sh`: external module entrypoint used by the ABK build hook.
- `module.conf`: module metadata, version, supported stages, and kernel lines.
- `scripts/install.py`: the installer. Copies the driver, wires
  Kconfig/Makefile, injects the gadget configfs hooks, and patches the KernelSU
  SELinux policy. Supports `install`, `verify`, `detect`, and `enable-config`.
  Every write is transactional and idempotent.
- `scripts/libabk.sh`: shell helpers shared by `setup.sh`.
- `tests/test_installer.py`: black-box installer tests against synthetic trees.
- `files/drivers/abk_fido_key/`: kernel driver source, Kconfig, and Makefile.
- `files/include/linux/abk_fido_key.h`: public kernel header used by the
  configfs injection point.
- `app/`, `build.gradle.kts`, `settings.gradle.kts`: minimal Android companion
  app project for the metadata-backed SQLite mirror.
- `agent/`: Go desktop bridge that relays CTAP frames from the phone to a local
  virtual HID device (`/dev/uhid` on Linux, `\\.\ABKFidoVhid` on Windows).
- `windows/`: the `abkfidovhid` virtual HID driver, `abkvhidctl.exe`, and the
  PowerShell packaging and install scripts the Windows agent depends on.

## Integration / 接入方式

### Prerequisites / 前置条件

- An ABK kernel build environment with `KERNEL_ROOT`, `DEFCONFIG`, and a
  `common/` kernel tree.
- A 5.15 or 6.1 kernel tree. Other lines are rejected.
- `python3` (3.9 or newer) available in the build environment.
- `CONFIG_USB_GADGET=y` in the target defconfig. The installer checks this
  before touching anything.
- Root access on-device if you want the companion app to mirror the SQLite
  database into `/metadata`.
- KernelSU is optional. When a KernelSU `selinux/rules.c` is found the installer
  injects the `/metadata` allow rules; otherwise that step is skipped with a
  warning and SELinux may deny the persisted credential store.

### ABK Usage / ABK 使用方法

Add the repository in ABK and enable both stages. This is the string to paste
into ABK's custom external modules field:

在 ABK 中添加仓库并同时启用两个阶段，把下面这行填进 ABK 的自定义外部模块输入框：

```text
module:https://github.com/fanziyun/ABK_FIDO_KEY_MODULE;after_patch|module:https://github.com/fanziyun/ABK_FIDO_KEY_MODULE;before_build
```

ABK clones the module's default branch with `git clone --depth 1` and does not
accept a branch or tag, so the default branch carries support for both kernel
lines rather than splitting them across branches.

ABK 用 `git clone --depth 1` 克隆模块的默认分支，且不接受分支或 tag 参数，
所以默认分支同时支持两条内核线，而不是拆成多个分支。

### Local Path Example / 本地路径示例

For a local checkout, ABK also accepts a filesystem path:

```bash
export USE_CUSTOM_EXTERNAL_MODULES="true"
export CUSTOM_EXTERNAL_MODULES="/abs/path/to/abk_fido_key_module;after_patch|/abs/path/to/abk_fido_key_module;before_build"
```

Then rebuild:

```bash
./rebuild.sh --reseed
```

### Manual Invocation / 手动调用

The installer runs standalone, which is the fastest way to check a tree before a
full build:

安装器可以独立运行，这是在完整编译前检查内核树最快的方式：

```bash
python3 scripts/install.py detect --kernel-root "$KERNEL_ROOT"
python3 scripts/install.py install --kernel-root "$KERNEL_ROOT" --defconfig "$DEFCONFIG"
python3 scripts/install.py enable-config --kernel-root "$KERNEL_ROOT" --defconfig "$DEFCONFIG"
python3 scripts/install.py verify --kernel-root "$KERNEL_ROOT" --defconfig "$DEFCONFIG"
```

## Stage Behavior / 阶段行为

- `after_patch`: install the driver sources, wire `drivers/Kconfig` and
  `drivers/Makefile`, inject the gadget configfs hooks, and patch the KernelSU
  SELinux policy when present.
- `before_build`: install (idempotent, so it is safe to repeat), enable the
  required `CONFIG_*` symbols in `DEFCONFIG`, then statically verify the sources,
  hooks, build wiring, and defconfig state. It does not compile the kernel.

Either stage alone produces a complete tree, but running both is recommended:
`after_patch` lands the sources early, and `before_build` is what enables the
config symbols and fails the build if anything is incomplete.

单独使用任一阶段都能得到完整的内核树，但推荐两个阶段都启用：`after_patch`
先把源码装进去，`before_build` 负责开启 config 符号，并在注入不完整时让构建失败。

Installation is transactional: if any step fails, every file the installer
touched is restored, so a failed run never leaves a half-patched tree.

安装是事务化的：任一步失败都会回滚安装器改过的所有文件，不会留下半成品内核树。

The hook injects `abk_fido_key_prepare_config()` into the gadget config bind
flow so the `abk_fido` function is added automatically when the USB gadget is
assembled.

这个 patch 会把 `abk_fido_key_prepare_config()` 注入 gadget config bind
流程，在组装 USB gadget 时自动添加 `abk_fido` function。

## Runtime Behavior / 运行期行为

- Adds one extra FIDO HID interface on top of the existing Android composite
  gadget.
- Exposes a misc debug node as `/dev/hidgX` where `X` is usually `0` to `3`.
- Exposes read-only status nodes under `/sys/kernel/abk_fido_key/`:
  `enabled`, `bound`, `udc`, `hid_dev`, `credential_count`, `last_error`,
  `last_trace`, `store_generation`.
- Exposes a write-only reload node under `/sys/kernel/abk_fido_key/reload_store`
  so userspace can force a reload from the metadata blob.
- Exposes a write-only restore trigger under
  `/sys/kernel/abk_fido_key/restore_metadata` so userspace can request a strict
  restore from the persisted store file without streaming the blob through
  sysfs.
- Exposes `/sys/kernel/abk_fido_key/store_blob` as a debug-only binary view of
  the current store; it is not the primary persistence or restore path on
  Android userspace.
- Supports CTAP HID `INIT`, `PING`, `WINK`, `CBOR`, and `CANCEL`.
- Exposes `/dev/abk_fido_ctap` as a transport-independent CTAP HID endpoint for
  the Android Credential Manager provider and the desktop LAN bridge.
- The companion registers as an Android 14+ Credential Manager passkey provider;
  browser requests are translated to CTAP2 and gated by the existing biometric
  approval flow.
- `agent/` contains a Go desktop bridge. Linux creates a `/dev/uhid` virtual
  FIDO HID device; the LAN session uses pairing-code-derived AES-GCM frames.
  Windows reaches the same interface through `\\.\ABKFidoVhid`, the control
  device of the `windows/vhid` driver.
- Implements CTAP2 `getInfo`, `makeCredential`, `getAssertion`, `clientPIN`
  (minimal), `reset`, and `selection`.
- Persists the kernel-side FIDO store blob at `/metadata/abk_fido_store.bin`.
- During build injection, the module patches KernelSU SELinux policy setup so
  the `kernel` domain can access that metadata blob without switching SELinux
  to permissive mode.
- The companion app mirrors the active blob into a SQLite database and keeps
  the SQLite mirror in `/metadata/abk_fido.db`.

## Biometric Authorization Flow / 指纹鉴权流程

Every `makeCredential` and `getAssertion` is gated on a local biometric
approval. The chain is implemented on both sides and needs no extra wiring:

每次 `makeCredential` 与 `getAssertion` 都需要本地指纹放行。内核侧与应用侧都已
实现，不需要额外接线：

1. A CTAP request arrives over USB HID and reaches
   `abk_fido_auth_begin_locked()`.
2. The kernel publishes the pending request on
   `/sys/kernel/abk_fido_key/auth_pending`, `auth_request_id`, and
   `auth_context`, then calls `am start-foreground-service` through
   `call_usermodehelper()` to raise the companion's `FidoSyncService`.
3. The kernel sleeps in `wait_event_interruptible_timeout()` for up to 30
   seconds, releasing its mutex first so the sysfs nodes stay readable.
4. The companion polls `auth_pending` every 750 ms, shows an androidx
   `BiometricPrompt`, and waits up to 25 seconds for the fingerprint.
5. The companion writes `allow <id>` or `deny <id>` to
   `/sys/kernel/abk_fido_key/auth_decision`.
6. The kernel wakes, signs with its in-kernel P-256 key, and returns the CTAP
   CBOR response over USB HID. An approval is cached for 10 seconds so a
   multi-step ceremony does not prompt repeatedly.

Additional nodes for this flow: `auth_gate_enabled` (read-write, disables the
gate), `auth_pending`, `auth_request_id`, `auth_context` (read-only), and
`auth_decision` (write-only).

To test the kernel half without a fingerprint, approve a pending request by hand:

不想走指纹时，可以手动放行一个待决请求，用来单独验证内核侧：

```bash
cat /sys/kernel/abk_fido_key/auth_context
echo "allow $(cat /sys/kernel/abk_fido_key/auth_request_id)" > /sys/kernel/abk_fido_key/auth_decision
cat /sys/kernel/abk_fido_key/last_trace
```

If `dmesg | grep abk_fido_key` shows a non-zero `bootstrap companion service
ret=`, the usermode helper could not launch the service. The flow still works in
that case because the companion polls `auth_pending` on its own; the helper only
shortens the wait.

如果 `dmesg | grep abk_fido_key` 里 `bootstrap companion service ret=` 非 0，
说明 usermode helper 没能拉起服务。此时流程仍可工作，因为应用本身也在轮询
`auth_pending`，helper 只是用来缩短等待。

## Validation / 验证方式

After a successful build and boot, check:

- the driver files were copied into `common/drivers/abk_fido_key`
- `CONFIG_ABK_FIDO_KEY=y` and related symbols are enabled
- `/sys/kernel/abk_fido_key/hid_dev` reports a `hidgX` device name
- `/sys/kernel/abk_fido_key/bound` becomes `1` after the gadget is bound
- `/dev/hidgX` exists for packet-level debugging
- a host WebAuthn registration raises the fingerprint prompt, and
  `dmesg | grep abk_fido_key` shows `auth pending` followed by `auth allowed`
- after a credential or PIN change, `/metadata/abk_fido_store.bin` exists
- writing `1` to `/sys/kernel/abk_fido_key/restore_metadata` increments
  `store_generation` and restores the expected `credential_count`
- `/sys/kernel/abk_fido_key/last_error` is empty after a successful restore
- `/sys/kernel/abk_fido_key/last_trace` reports the metadata restore path
- after the companion app sync runs, `/metadata/abk_fido.db` exists

Build-time checks before flashing:

刷机前的构建期检查：

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/install.py verify --kernel-root "$KERNEL_ROOT" --defconfig "$DEFCONFIG"
grep -n abk_fido_key "$KERNEL_ROOT/common/drivers/usb/gadget/configfs.c"
grep -E 'CONFIG_ABK_FIDO_KEY=|CONFIG_CRYPTO_ECC=' "$DEFCONFIG"
```

## GitHub Release Automation / GitHub 自动发布

- `.github/workflows/build-companion-app.yml` builds debug and release APKs on
  GitHub Actions.
- The workflow signs the release APK from GitHub secrets, then uses `gh release`
  to create or update the target release and upload
  `abk-fido-companion-release.apk`.
- Required repository secrets:
  `ANDROID_SIGNING_KEYSTORE_BASE64`,
  `ANDROID_SIGNING_KEYSTORE_PASSWORD`,
  `ANDROID_SIGNING_KEY_ALIAS`,
  `ANDROID_SIGNING_KEY_PASSWORD`.
- Pushes to `main` or `master` refresh the rolling `latest` release. Pushing a
  `v*` tag publishes the asset to the matching tagged release.
- The job is skipped on forks, because signing secrets are not inherited and an
  unsigned asset is worse than none. Add the four secrets above and run the
  workflow manually (`workflow_dispatch`) to publish from a fork.
- `ABK_EXTENSION_COMPANION_DOWNLOAD_URL` in `module.conf` still points at the
  upstream signed release: this fork adds a diagnostics screen but no change the
  kernel module depends on, and only upstream publishes a signed asset. Repoint
  it after publishing here.

- 该 job 在 fork 上会跳过，因为签名 secret 不会被继承，发一个未签名的产物比不发更糟。
  想从 fork 发布，需要自己配置上面四个 secret 并手动触发 `workflow_dispatch`。
- `module.conf` 里的 `ABK_EXTENSION_COMPANION_DOWNLOAD_URL` 仍指向上游已签名的
  release：本 fork 只额外加了诊断界面，没有内核模块依赖的改动，而且只有上游会发布
  已签名产物。等这里自己发布后再改指向。

## Development / 开发

The installer and its tests run on any machine with Python 3.9 or newer; no
kernel tree or cross toolchain is needed:

安装器与测试在任何有 Python 3.9+ 的机器上都能跑，不需要内核树或交叉编译工具链：

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m py_compile scripts/install.py tests/test_installer.py
bash -n setup.sh scripts/libabk.sh
shellcheck --severity=warning setup.sh scripts/libabk.sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
```

The tests use synthetic trees carrying only the anchors the installer owns, for
both the 5.15 and 6.1 layouts. They check wiring, injection, idempotency,
rollback, and every rejection path. They do not compile a kernel.

测试使用只包含安装器关心的锚点的合成内核树，覆盖 5.15 与 6.1 两种布局，校验接线、
注入、幂等、回滚以及所有拒绝路径；但不编译内核。

The desktop agent and the companion app carry their own tests, which need a Go
toolchain and the Android SDK respectively:

desktop agent 与 companion app 各自带测试，分别需要 Go 工具链与 Android SDK：

```bash
(cd agent && go test ./...)
./gradlew testDebugUnitTest assembleDebug
```

## Metadata / 元数据

Public module metadata lives in `module.conf` and is intended to match the
published repository. Companion-app metadata is also exported there so ABK can
offer the FIDO SQLite mirror APK alongside the kernel module.

公开模块元数据位于 `module.conf`，并且应与发布后的仓库保持一致。

## Current Limits / 当前边界

- No Windows Hello support.
- No CTAP1/U2F `MSG` handling. `U2F_V2` is advertised in `getInfo`, but the
  transport only implements CTAP2 `CBOR`.
- The kernel waits up to 30 s for a decision while the companion's prompt times
  out at 25 s. With the 750 ms poll interval the worst case is about 25.75 s, so
  the margin is roughly 4 s. If timeouts appear on a device, lower the app's
  25 s rather than raising the kernel's 30 s: the USB host has its own CTAPHID
  deadline.
- Unplugging the cable while a request is waiting for a fingerprint can block
  gadget teardown for the remainder of the 30 s wait: `abk_fido_unbind()` calls
  `cancel_work_sync()` without waking the sleeping thread. This predates the
  5.15 support and affects 6.1 identically.
- The installer validates source anchors and defconfig state. It does not
  compile, link, or boot a kernel, so a passing `verify` is not evidence that the
  build succeeds or the device works.
- The LAN relay needs a virtual HID device on the desktop, and creating one is
  privileged on both platforms: on Linux the agent uses `/dev/uhid` and must run
  as root; on Windows it needs the `abkfidovhid` driver from
  [Windows virtual HID driver](#windows-virtual-hid-driver--windows-虚拟-hid-驱动)
  installed and must run elevated. That driver is self-signed here, so the
  machine has to have test signing on (which means Secure Boot off) — if that is
  not acceptable, connect the phone over USB instead, where the gadget is a
  native FIDO HID key that needs no driver.
  局域网中转在 Windows 上需要安装本仓库的 `abkfidovhid` 虚拟 HID 驱动，并开启测试签名
  （需关闭安全启动）；若不便如此，请改用 USB 连接手机。

- 不支持 Windows Hello。
- 没有实现 CTAP1/U2F 的 `MSG`；`getInfo` 里虽然声明了 `U2F_V2`，传输层只处理
  CTAP2 的 `CBOR`。
- 内核最多等 30 秒，应用侧提示超时是 25 秒，加上 750ms 轮询间隔，最坏约
  25.75 秒，余量约 4 秒。设备上如果频繁超时，优先调小应用的 25 秒而不是调大
  内核的 30 秒，因为 USB 宿主自己也有 CTAPHID 超时。
- 等待指纹期间拔线，可能让 gadget 拆卸阻塞到 30 秒等待结束：
  `abk_fido_unbind()` 只调用了 `cancel_work_sync()`，没有唤醒正在睡眠的线程。
  这是 5.15 支持之前就存在的问题，6.1 上行为相同。
- 安装器只校验源码锚点和 defconfig 状态，不编译、不链接、不启动内核；
  `verify` 通过不等于能编译成功或设备可用。

## Windows virtual HID driver / Windows 虚拟 HID 驱动

Windows WebAuthn only enumerates real HID devices, so `windows/` contains the
driver that gives the LAN relay something for browsers to find:

- `windows/vhid/` — `abkfidovhid.sys`, a KMDF function driver built on the
  Virtual HID Framework (`vhf.sys` is added as a lower filter). It publishes a
  CTAP HID device (usage page `0xF1D0`, 64-byte input and output reports) and
  the control device `\\.\ABKFidoVhid`, whose security descriptor admits only
  SYSTEM and Administrators. The WDK comes from the NuGet packages pinned in
  `packages.config`, so no machine-wide WDK install is required.
- `windows/tools/abkvhidctl/` — `abkvhidctl.exe`, which creates, inspects and
  removes the root-enumerated devnode the driver binds to (`abkvhidctl install
  <inf>` / `remove` / `status`). `pnputil` cannot invent a devnode for hardware
  that does not exist, which is what a software-only HID source needs.
- `windows/scripts/` — `Sign-Package.ps1` (packages and test-signs with a
  freshly generated self-signed certificate), plus
  `Install-AbkFidoVhid.ps1` / `Uninstall-AbkFidoVhid.ps1`.

`.github/workflows/build-windows-vhid.yml` builds and test-signs all of it on
`windows-latest` and uploads the `abk-fido-vhid-x64` artifact. To install, from
an elevated PowerShell prompt in the extracted artifact:

```powershell
.\Install-AbkFidoVhid.ps1 -EnableTestSigning   # reboot, then run it again
.\abkvhidctl.exe status
```

The certificate is generated on the machine that runs the build, so a
self-signed package will only load while test signing is on; the installer
checks Secure Boot and the test-signing flag and reports what is missing instead
of changing boot configuration on its own. Devnode problem code 52 means the
signature was rejected. Then run the agent elevated, as usual:

```powershell
sudo .\abk-fido-agent-windows-amd64.exe
```

To back it all out: `.\Uninstall-AbkFidoVhid.ps1 -RemoveDriverPackage
-RemoveCertificate`, then `bcdedit /set testsigning off`.

## LAN pairing / 局域网配对

The companion stores a six-to-twelve digit pairing code at
`/metadata/abk_fido_pairing_code` and starts an encrypted TCP listener on port
`38741`. The desktop agent discovers phones automatically when `-phone` is
omitted, lets the user choose a discovered device, and asks that phone to show
the pairing code in a confirmation window:

```bash
go run ./agent
```

For scripted use, the explicit form remains supported:

```bash
go run ./agent -pairing 123456 -phone 192.168.1.20:38741
```

The code is used as a PSK input to PBKDF2-HMAC-SHA256 and every frame is
authenticated and encrypted with AES-GCM. Do not expose the listener outside a
trusted LAN; rotate the code by deleting the metadata file and restarting the
companion service.
