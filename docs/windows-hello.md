# Windows Hello with the ABK FIDO key / ABK FIDO 钥匙的 Windows Hello 实测

How to verify — and, when it fails, diagnose — Windows Hello security-key
sign-in against a phone built with `ABK_FIDO_KEY_MODULE` 0.3.0+.

本文是 0.3.0+ 版本在 Windows 上实测安全密钥登录的步骤，以及枚举不到钥匙时的
排障清单。

## Prerequisites / 前置条件

- Windows 10 1903+ or Windows 11 with a Windows Hello **PIN** already set
  (Settings → Accounts → Sign-in options → PIN).
  Windows 需已设置 Hello PIN（设置 → 账户 → 登录选项 → PIN）。
- A phone build carrying `CONFIG_ABK_FIDO_KEY=y` and
  `CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH=y` (the module's `before_build`
  stage fails the build if either is missing).
  手机内核需启用上述两个配置（缺失时模块在 before_build 阶段会直接报错）。
- The 0.3.0 companion app (the store blob layout changed in v2).
  配套 App 需 0.3.0（存储格式升级为 v2）。
- USB path only: no driver, no test signing needed on Windows. The LAN relay
  path additionally needs the `abkfidovhid` driver, which is unrelated to
  Windows Hello enumeration over USB.
  只谈 USB 路径：Windows 端无需任何驱动。LAN 中转路径才需要 vhid 驱动。

## Step 0 — on-phone crypto self-test / 手机端密码学自检

Before touching Windows, confirm the offline-unlock crypto works on the phone:

```bash
adb shell su -c 'cat /sys/kernel/abk_fido_key/hmac_selftest'
# expect ecdh:ok, salt_auth:ok, salt_dec:ok, outputs:ok, output_enc:ok,
# and the final line hmac-secret:ok
```

## Step 1 — USB enumeration / USB 枚举

Plug the phone in, then check both ends.

### Phone side / 手机端

```bash
adb shell su -c 'cat /sys/kernel/abk_fido_key/attach_state'
adb shell su -c 'cat /sys/kernel/abk_fido_key/bound /sys/kernel/abk_fido_key/hid_dev'
adb shell su -c 'dmesg | grep abk_fido_key | tail -n 20'
```

`attach_state` decision table / 状态对照表:

| attach_state | meaning / 含义 | fix / 处理 |
|---|---|---|
| `not_configured` | the configfs injection never ran on this boot | verify the module was in the build (grep `CONFIG_ABK_FIDO_KEY` in `/proc/config.gz`), and that `drivers/usb/gadget/configfs.c` contains `abk_fido_key_prepare_config` |
| `auto_attach_disabled` | `CONFIG_ABK_FIDO_KEY_GADGET_AUTO_ATTACH` is off | enable it in the defconfig and rebuild |
| `get_instance_failed:<err>` / `get_function_failed:<err>` | the `abk_fido` function could not be instantiated | read `dmesg` for the underlying failure (usually registration order) |
| `attached` | function added, bind not reached yet | re-plug the USB cable and read again |
| `bound_iface:N` | bound, host has not selected the configuration yet | re-plug / replug the cable, check the Windows side |
| `online_iface:N` | interface is live on the wire | proceed to the Windows checks |

Note: USB gadget rebind happens on (re)plug. If the module was not in the
boot image or the cable was already in during an upgrade, unplug and replug.

注意：gadget 在插拔时才重新 bind。升级后一定要重新插拔一次。

### Windows side / Windows 端

1. **Device Manager / 设备管理器**: the composite device should be error-free
   (no code 10/43). Look for a new **USB Input Device / HID-compliant device**.
2. Quick HID inventory:

   ```powershell
   Get-PnpDevice -Class HIDClass | Where-Object Status -eq 'OK' | Format-Table FriendlyName, InstanceId
   ```

   If a fresh HID device appears after plugging the phone, the interface is
   on the wire.
3. If nothing appears at all, the FIDO interface is missing from the USB
   configuration — go back to the `attach_state` table (this is branch A).
4. If a HID device appears but Windows Hello still does not list the key,
   capture the WebAuthN operational log: Event Viewer →
   Applications and Services Logs → Microsoft → Windows → WebAuthN →
   Operational (branch B).
5. Key listing check: Settings → Accounts → Sign-in options → Security key →
   **Manage**. The key should appear as "ABK Security Key".

## Step 2 — register the key / 注册钥匙

1. Settings → Accounts → Sign-in options → Security key → Manage → **Add**.
2. Windows runs the device-selection ceremony (`rp.id = "SelectDevice"`), then
   registers a resident credential at `login.microsoft.com` and asks for the
   `hmac-secret` extension. The phone must show its biometric / screen-lock
   prompt for **each** ceremony step — approve both.
3. Watch the phone: two approvals are normal (ceremony + registration).
4. `credential_count` under `/sys/kernel/abk_fido_key/` increments, and the
   new credential carries a non-zero hmac-secret, which is what makes offline
   unlock possible later.

## Step 3 — online sign-in / 在线登录

1. Lock the PC (Win+L), pick **Security key**, tap the phone when asked.
2. The phone must prompt again (Windows sends `getAssertion` with `up`/`uv`
   and an allowList; the driver answers with the `user` object and the UV
   flag). Approve → Windows unlocks.

## Step 4 — offline unlock / 离线解锁

1. Disconnect the PC from every network (disable Wi-Fi, pull Ethernet, or
   enable airplane mode on the router).
2. Lock, choose Security key, approve on the phone.
3. Windows now also sends `hmacGetSecret` (keyAgreement + saltEnc + saltAuth);
   the driver verifies saltAuth, unwraps the salts and returns the encrypted
   HMAC outputs, all signed inside authData. If this unlocks, hmac-secret is
   correct end to end.

Known behaviour / 已知行为:

- Credentials registered with a ≤0.2.0 build (store v1) have no hmac-secret
  and answer `CTAP2_ERR_INVALID_OPTION`; Windows treats them as online-only.
  Delete and re-register them to enable offline unlock.
- A refused/denied prompt blocks requests for 3 s (`auth_cooldown`), which
  Windows may surface as a generic failure — wait and retry.

## Automated checks / 自动化检查

Host-side (no phone, no Windows):

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
(cd agent && go test ./...)
```

`tests/test_hmac_secret.py` re-derives the hmac-secret golden vectors with an
independent implementation and byte-compares them with the vectors embedded in
the driver's `hmac_selftest`; `tests/test_windows_hello.py` pins the Windows
wire shapes (F1D0 report descriptor, INIT reply bytes, broadcast CID,
SelectDevice, user-object inclusion, hmac-secret response placement).
