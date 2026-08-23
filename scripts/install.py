#!/usr/bin/env python3
"""Install and verify the ABK FIDO key source integration.

The module is built into the kernel image, not as a loadable object. This
installer copies the driver into the target tree, wires it into the drivers
Kconfig/Makefile, injects the USB gadget configfs auto-attach hooks, and
optionally relaxes the KernelSU SELinux policy for the /metadata store.

Every write is owned by MARKER, transactional, and idempotent: re-running
install on an already-installed tree is a no-op, and a failure part-way through
restores every file the installer touched.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


MARKER = "ABK_FIDO_KEY_V1"

# The driver's only kernel-line sensitivity is the internal ECC header path,
# which core.c resolves with __has_include. Both lines below are verified.
SUPPORTED_KERNELS = {"5.15", "6.1"}

# Where the internal ECC header lives per kernel line. install validates that
# the target tree actually matches, so a silent __has_include miss cannot pass.
ECC_HEADER_BY_LINE = {
    "5.15": "crypto/ecc.h",
    "6.1": "include/crypto/internal/ecc.h",
}

DRIVER_DIR = "drivers/abk_fido_key"
PUBLIC_HEADER = "include/linux/abk_fido_key.h"

KCONFIG_SOURCE_LINE = 'source "drivers/abk_fido_key/Kconfig"'
MAKEFILE_OBJ_LINE = "obj-$(CONFIG_ABK_FIDO_KEY) += abk_fido_key/"

CONFIGFS_INCLUDE = "#include <linux/abk_fido_key.h>"

# Driver sources copied verbatim into the kernel tree. Each must carry MARKER.
DRIVER_SOURCES = ("Kconfig", "Makefile", "core.c")

# Needles verify() requires in the installed core.c. The gadget function is
# declared with DECLARE_USB_FUNCTION and registered from the driver's own
# module_init: DECLARE_USB_FUNCTION_INIT would emit a second module_init and
# collide with abk_fido_core_init in a built-in driver.
CORE_NEEDLES = (
    MARKER,
    "DECLARE_USB_FUNCTION(abk_fido, abk_fido_alloc_inst, abk_fido_alloc);",
    "usb_function_register(&abk_fidousb_func)",
    "usb_function_unregister(&abk_fidousb_func)",
    "abk_fido_auth_begin_locked",
    "abk_fido_bootstrap_companion_service",
)

# DECLARE_USB_FUNCTION_INIT expands to its own module_init/module_exit pair, so
# using it here would collide with abk_fido_core_init/exit at link time.
CORE_FORBIDDEN_NEEDLES = ("DECLARE_USB_FUNCTION_INIT",)

_ACTIVE_TRANSACTION: "InstallTransaction | None" = None
_VALIDATION_ONLY = False


class InstallError(RuntimeError):
    pass


class InstallTransaction:
    """Restore every installer-owned write if installation does not complete."""

    def __init__(self) -> None:
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._backup_root: Path | None = None
        self._files: dict[Path, Path | None] = {}
        self._missing_directories: set[Path] = set()

    def __enter__(self) -> "InstallTransaction":
        global _ACTIVE_TRANSACTION

        if _ACTIVE_TRANSACTION is not None:
            raise InstallError("nested installer transaction is unsupported")
        self._temporary = tempfile.TemporaryDirectory(prefix="abk-fido-key-install-")
        self._backup_root = Path(self._temporary.name)
        _ACTIVE_TRANSACTION = self
        return self

    def _record_missing_directories(self, path: Path) -> None:
        cursor = path
        while not cursor.exists():
            if cursor.is_symlink():
                raise InstallError(f"refusing broken symlink in installer target: {cursor}")
            self._missing_directories.add(cursor)
            parent = cursor.parent
            if parent == cursor:
                break
            cursor = parent
        if cursor.exists() and not cursor.is_dir():
            raise InstallError(f"installer target parent is not a directory: {cursor}")

    def record_directory(self, path: Path) -> None:
        if path.is_symlink():
            raise InstallError(f"refusing symlink installer directory target: {path}")
        if path.exists():
            if not path.is_dir():
                raise InstallError(f"installer directory target is not a directory: {path}")
            return
        self._record_missing_directories(path)

    def record_file(self, path: Path) -> None:
        if path in self._files:
            return
        if path.is_symlink():
            raise InstallError(f"refusing symlink installer file target: {path}")
        self._record_missing_directories(path.parent)
        if path.exists():
            if not path.is_file():
                raise InstallError(f"installer file target is not a regular file: {path}")
            assert self._backup_root is not None
            backup = self._backup_root / str(len(self._files))
            shutil.copy2(path, backup)
            self._files[path] = backup
        else:
            self._files[path] = None

    def _rollback(self) -> None:
        failures: list[str] = []
        for path, backup in reversed(tuple(self._files.items())):
            try:
                if backup is None:
                    if path.is_symlink() or path.is_file():
                        path.unlink()
                    elif path.exists():
                        raise OSError("new installer file was replaced by a directory")
                    continue
                if path.is_symlink():
                    path.unlink()
                elif path.exists() and not path.is_file():
                    raise OSError("installer file was replaced by a directory")
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup, path)
            except OSError as exc:
                failures.append(f"{path}: {exc}")

        for path in sorted(
            self._missing_directories, key=lambda item: len(item.parts), reverse=True
        ):
            try:
                path.rmdir()
            except FileNotFoundError:
                pass
            except OSError as exc:
                failures.append(f"{path}: {exc}")

        if failures:
            raise InstallError("installation rollback failed: " + "; ".join(failures))

    def __exit__(self, exc_type: object, exc: BaseException | None, traceback: object) -> bool:
        global _ACTIVE_TRANSACTION

        rollback_error: InstallError | None = None
        try:
            if exc is not None:
                try:
                    self._rollback()
                except InstallError as rollback_exc:
                    rollback_error = rollback_exc
                else:
                    if self._files or self._missing_directories:
                        print("ABK FIDO Key: installation rolled back", file=sys.stderr)
        finally:
            _ACTIVE_TRANSACTION = None
            if self._temporary is not None:
                self._temporary.cleanup()

        if rollback_error is not None:
            raise rollback_error from exc
        return False


@dataclass(frozen=True)
class Layout:
    kernel_root: Path
    common: Path
    version: str


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise InstallError(f"required file not found: {path}") from exc


def write(path: Path, text: str) -> None:
    old = path.read_text(encoding="utf-8") if path.exists() else None
    if old == text:
        return
    if _VALIDATION_ONLY:
        raise InstallError(f"incomplete FIDO injection: validation would update {path}")
    if _ACTIVE_TRANSACTION is not None:
        _ACTIVE_TRANSACTION.record_file(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"ABK FIDO Key: updated {path}")


_C_STRING = r'"(?:\\.|[^"\\])*"'
_C_CHAR = r"'(?:\\.|[^'\\])*'"
_C_LINE_COMMENT = r"//[^\n]*"
_C_BLOCK_COMMENT = r"/\*.*?\*/"
_C_LEXEME_PATTERN = re.compile(
    "|".join((_C_STRING, _C_CHAR, _C_LINE_COMMENT, _C_BLOCK_COMMENT)),
    flags=re.DOTALL,
)


def _masked_lexeme(match: re.Match[str]) -> str:
    return "".join("\n" if character == "\n" else " " for character in match.group())


def mask_c_comments(text: str) -> str:
    """Blank comments, preserving offsets and line numbers.

    Anchor searches run against the masked text so a needle that only appears
    inside a comment cannot be mistaken for real code. String literals are kept
    because some anchors are themselves literals, e.g. an #include line.
    """

    def mask(match: re.Match[str]) -> str:
        token = match.group()
        if token.startswith("//") or token.startswith("/*"):
            return _masked_lexeme(match)
        return token

    return _C_LEXEME_PATTERN.sub(mask, text)


def mask_c_comments_and_literals(text: str) -> str:
    """Blank comments and string literals, preserving offsets and line numbers."""
    return _C_LEXEME_PATTERN.sub(_masked_lexeme, text)


def find_live_occurrences(text: str, needle: str) -> list[int]:
    masked = mask_c_comments(text)
    offsets: list[int] = []
    start = masked.find(needle)
    while start != -1:
        offsets.append(start)
        start = masked.find(needle, start + 1)
    return offsets


def require_single_live_occurrence(path: Path, text: str, needle: str, description: str) -> int:
    offsets = find_live_occurrences(text, needle)
    if not offsets:
        raise InstallError(f"{description} not found in {path}")
    if len(offsets) > 1:
        raise InstallError(
            f"{description} is ambiguous in {path}: {len(offsets)} matches"
        )
    return offsets[0]


def kernel_common(root: Path) -> Path:
    common = root / "common"
    if (common / "Makefile").is_file():
        return common
    if (root / "Makefile").is_file():
        return root
    raise InstallError(f"kernel Makefile not found below {root}")


def kernel_version(common: Path) -> str:
    makefile = read(common / "Makefile")
    values: dict[str, str] = {}
    for key in ("VERSION", "PATCHLEVEL"):
        match = re.search(rf"(?m)^{key}\s*=\s*(\d+)\s*$", makefile)
        if not match:
            raise InstallError(f"cannot read {key} from {common / 'Makefile'}")
        values[key] = match.group(1)
    version = f"{values['VERSION']}.{values['PATCHLEVEL']}"
    if version not in SUPPORTED_KERNELS:
        raise InstallError(
            f"unsupported kernel line {version}; expected one of "
            f"{', '.join(sorted(SUPPORTED_KERNELS))}"
        )
    return version


def validate_ecc_header(layout: Layout) -> None:
    """Confirm the tree really has the ECC header core.c will select.

    core.c picks the header with __has_include. If neither path exists the
    driver would fail to compile deep inside the kernel build, so check here
    where the error is actionable.
    """
    expected = ECC_HEADER_BY_LINE[layout.version]
    if not (layout.common / expected).is_file():
        raise InstallError(
            f"kernel {layout.version} is missing the internal ECC header {expected}; "
            "CONFIG_CRYPTO_ECC sources are required by the FIDO driver"
        )
    unexpected = {
        path for path in ECC_HEADER_BY_LINE.values() if path != expected
    }
    present = sorted(path for path in unexpected if (layout.common / path).is_file())
    if present:
        raise InstallError(
            f"kernel {layout.version} unexpectedly provides {', '.join(present)}; "
            "the tree does not match its reported kernel line"
        )


def discover(root: Path) -> Layout:
    common = kernel_common(root)
    return Layout(root, common, kernel_version(common))


def copy_sources(layout: Layout, module_root: Path) -> None:
    source = module_root / "files" / DRIVER_DIR
    target = layout.common / DRIVER_DIR
    if not source.is_dir():
        raise InstallError(f"module source directory missing: {source}")
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise InstallError(f"refusing conflicting driver source target: {target}")

    texts: dict[str, str] = {}
    for name in DRIVER_SOURCES:
        text = read(source / name)
        if MARKER not in text:
            raise InstallError(f"module source is missing ownership marker: {source / name}")
        texts[name] = text

    if target.is_dir():
        owned = set(DRIVER_SOURCES)
        for existing in target.iterdir():
            if existing.is_symlink():
                raise InstallError(f"refusing symlink in driver source target: {existing}")
            if existing.is_dir():
                raise InstallError(
                    f"refusing unexpected directory in driver source target: {existing}"
                )
            if existing.name in owned:
                if MARKER in read(existing):
                    continue
                raise InstallError(f"refusing non-ABK file in driver source target: {existing}")
            if not _build_artifact(existing):
                raise InstallError(
                    f"refusing unexpected file in driver source target: {existing}"
                )

    if _ACTIVE_TRANSACTION is not None:
        _ACTIVE_TRANSACTION.record_directory(target)
    if not _VALIDATION_ONLY:
        target.mkdir(parents=True, exist_ok=True)
    for name, text in texts.items():
        # Never preserve the checkout mtime: Kbuild must see a fresh timestamp
        # when content changes so stale objects are rebuilt.
        write(target / name, text)

    header_source = module_root / "files" / PUBLIC_HEADER
    header_text = read(header_source)
    if MARKER not in header_text:
        raise InstallError(f"module source is missing ownership marker: {header_source}")
    write(layout.common / PUBLIC_HEADER, header_text)


_BUILD_ARTIFACT_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"\.[^/]+\.cmd",
        r"[^/]+\.o",
        r"[^/]+\.o\.d",
        r"modules\.order",
        r"[^/]+\.mod",
        r"[^/]+\.mod\.c",
    )
)


def _build_artifact(path: Path) -> bool:
    return any(pattern.fullmatch(path.name) for pattern in _BUILD_ARTIFACT_PATTERNS)


def append_line_once(path: Path, line: str) -> None:
    """Append a build-wiring line unless it is already present.

    drivers/Kconfig ends with `endmenu`, so the sourced Kconfig lands at top
    level rather than inside the "Device Drivers" menu. That is exactly how the
    module already ships on 6.1, and Kconfig accepts a top-level source, so the
    placement is preserved deliberately rather than "fixed".
    """
    text = read(path)
    if any(existing.strip() == line for existing in text.splitlines()):
        return
    suffix = "" if text.endswith("\n") or not text else "\n"
    write(path, f"{text}{suffix}{line}\n")


def wire_build(layout: Layout) -> None:
    append_line_once(layout.common / "drivers/Kconfig", KCONFIG_SOURCE_LINE)
    append_line_once(layout.common / "drivers/Makefile", MAKEFILE_OBJ_LINE)


CONFIGFS_INCLUDE_ANCHOR = '#include "u_os_desc.h"'
CONFIGFS_PREPARE_ANCHOR = "\t\tlist_for_each_entry_safe(f, tmp, &cfg->func_list, list) {"
CONFIGFS_RELEASE_ANCHOR = (
    "static void gadget_config_attr_release(struct config_item *item)\n"
    "{\n"
    "\tstruct config_usb_cfg *cfg = to_config_usb_cfg(item);\n"
)

CONFIGFS_PREPARE_BLOCK = "".join(
    (
        "#ifdef CONFIG_ABK_FIDO_KEY\n",
        f"\t\t/* {MARKER}: attach the FIDO HID function to this gadget config. */\n",
        "\t\tret = abk_fido_key_prepare_config(cdev, c, &cfg->func_list);\n",
        "\t\tif (ret) {\n",
        # The \\n below must reach the kernel source as a literal escape.
        '\t\t\tpr_err("abk_fido_key: prepare_config failed: %d\\n", ret);\n',
        "\t\t\tret = 0;\n",
        "\t\t}\n",
        "#endif\n",
        "\n",
    )
)

CONFIGFS_RELEASE_BLOCK = "".join(
    (
        "\n",
        "#ifdef CONFIG_ABK_FIDO_KEY\n",
        f"\t/* {MARKER}: release any FIDO function still queued on this config. */\n",
        "\tabk_fido_key_release_config(&cfg->func_list);\n",
        "#endif\n",
    )
)

CONFIGFS_MARKERS = (
    f"{MARKER}: attach the FIDO HID function",
    f"{MARKER}: release any FIDO function",
)


def patch_configfs(layout: Layout) -> None:
    """Inject the gadget auto-attach hooks into drivers/usb/gadget/configfs.c.

    The driver does not register its own configfs group. It exports
    abk_fido_key_prepare_config()/abk_fido_key_release_config() and relies on
    these two call sites, so the injection is mandatory for the gadget to appear.
    """
    path = layout.common / "drivers/usb/gadget/configfs.c"
    text = read(path)

    installed = [marker for marker in CONFIGFS_MARKERS if marker in text]
    has_include = CONFIGFS_INCLUDE in text
    if len(installed) == len(CONFIGFS_MARKERS) and has_include:
        _validate_configfs_installed(path, text)
        return
    if installed or has_include:
        raise InstallError(
            f"conflicting or partial ABK FIDO injection in {path}; "
            "restore the file from the kernel source tree and re-run"
        )
    if "abk_fido_key_prepare_config" in text or "abk_fido_key_release_config" in text:
        raise InstallError(
            f"unmarked ABK FIDO injection already present in {path}; "
            "restore the file from the kernel source tree and re-run"
        )

    updated = text

    offset = require_single_live_occurrence(
        path, updated, CONFIGFS_INCLUDE_ANCHOR, "configfs include anchor"
    )
    end = updated.index("\n", offset) + 1
    updated = updated[:end] + CONFIGFS_INCLUDE + "\n" + updated[end:]

    offset = require_single_live_occurrence(
        path, updated, CONFIGFS_PREPARE_ANCHOR, "configfs gadget bind anchor"
    )
    _require_identifiers_in_scope(path, updated, offset, ("cdev", "cfg", "ret", "c"))
    updated = updated[:offset] + CONFIGFS_PREPARE_BLOCK + updated[offset:]

    offset = require_single_live_occurrence(
        path, updated, CONFIGFS_RELEASE_ANCHOR, "configfs config release anchor"
    )
    end = offset + len(CONFIGFS_RELEASE_ANCHOR)
    updated = updated[:end] + CONFIGFS_RELEASE_BLOCK + updated[end:]

    write(path, updated)


def _validate_configfs_installed(path: Path, text: str) -> None:
    for marker in CONFIGFS_MARKERS:
        if text.count(marker) != 1:
            raise InstallError(f"duplicate ABK FIDO injection in {path}: {marker}")
    for needle in (
        CONFIGFS_INCLUDE,
        "abk_fido_key_prepare_config(cdev, c, &cfg->func_list)",
        "abk_fido_key_release_config(&cfg->func_list)",
    ):
        if text.count(needle) != 1:
            raise InstallError(f"incomplete FIDO injection: {needle!r} in {path}")
    include_at = text.index(CONFIGFS_INCLUDE)
    for marker in CONFIGFS_MARKERS:
        if include_at > text.index(marker):
            raise InstallError(f"ABK public header appears after its hook in {path}")


_MEMBER_ACCESS_PATTERN = re.compile(r"(?:->|\.)\s*[A-Za-z_]\w*")


def _mask_member_accesses(text: str) -> str:
    """Blank `->member` and `.member` so a member name is not read as a local.

    Without this, `gi->cdev.configs` would satisfy a search for a declaration of
    `cdev` even after the real declaration was removed.
    """
    return _MEMBER_ACCESS_PATTERN.sub(_masked_lexeme, text)


def _require_identifiers_in_scope(
    path: Path, text: str, offset: int, identifiers: tuple[str, ...]
) -> None:
    """Check the enclosing function declares every identifier the hook uses."""
    masked = mask_c_comments_and_literals(text)
    start = masked.rfind("\n}\n", 0, offset)
    scope = _mask_member_accesses(masked[start if start != -1 else 0 : offset])
    for identifier in identifiers:
        if not re.search(rf"\b{re.escape(identifier)}\b", scope):
            raise InstallError(
                f"configfs bind scope in {path} does not provide {identifier!r}; "
                "the anchor moved and the injection would not compile"
            )


KSU_RULES_CANDIDATES = (
    "drivers/kernelsu/selinux/rules.c",
    "drivers/kernelsu/kernel/selinux/rules.c",
    "drivers/staging/kernelsu/selinux/rules.c",
    "KernelSU/kernel/selinux/rules.c",
    "kernel/selinux/rules.c",
)

SEPOLICY_MARKER = f"{MARKER}: metadata store access"
SEPOLICY_BLOCK = f"""
    /* {SEPOLICY_MARKER} */
    ksu_allow(db, "kernel", "metadata_file", "dir", "search");
    ksu_allow(db, "kernel", "metadata_file", "file", "open");
    ksu_allow(db, "kernel", "metadata_file", "file", "read");
    ksu_allow(db, "kernel", "metadata_file", "file", "write");
    ksu_allow(db, "kernel", "metadata_file", "file", "getattr");
"""

# Any ksu_allow() call site works as an anchor; matching the containing function
# rather than one upstream comment keeps this working across KernelSU variants.
SEPOLICY_ANCHOR_PATTERN = re.compile(
    r"(?m)^[ \t]*ksu_allow\(db,[^\n]*\n"
)


def find_ksu_rules(layout: Layout) -> Path | None:
    for relative in KSU_RULES_CANDIDATES:
        candidate = layout.common / relative
        if candidate.is_file():
            return candidate
        candidate = layout.kernel_root / relative
        if candidate.is_file():
            return candidate
    return None


def patch_sepolicy(layout: Layout) -> Path | None:
    """Grant the kernel domain access to /metadata when KernelSU is present.

    KernelSU is optional: without it the driver still works, but the persisted
    credential store under /metadata may be denied by SELinux. Returns the
    patched path, or None when no KernelSU tree was found.
    """
    path = find_ksu_rules(layout)
    if path is None:
        return None

    text = read(path)
    if SEPOLICY_MARKER in text:
        if text.count(SEPOLICY_MARKER) != 1:
            raise InstallError(f"duplicate ABK FIDO sepolicy injection in {path}")
        return path
    if 'ksu_allow(db, "kernel", "metadata_file"' in text:
        raise InstallError(
            f"unmarked ABK FIDO sepolicy injection already present in {path}; "
            "restore the file from the KernelSU source tree and re-run"
        )

    masked = mask_c_comments_and_literals(text)
    matches = list(SEPOLICY_ANCHOR_PATTERN.finditer(masked))
    if not matches:
        raise InstallError(f"no ksu_allow() anchor found in {path}")
    end = matches[-1].end()
    write(path, text[:end] + SEPOLICY_BLOCK + text[end:])
    return path


REQUIRED_CONFIGS = (
    "ABK_FIDO_KEY",
    "ABK_FIDO_KEY_CTAP2",
    "ABK_FIDO_KEY_GADGET_AUTO_ATTACH",
    "ABK_FIDO_KEY_PERSIST_METADATA",
    "ABK_FIDO_KEY_PERSIST_ADB_DATA",
    # The driver is built in, so its crypto providers must be built in too.
    # CRYPTO_ECC is a tristate; =m would leave the built-in driver unlinked.
    "CRYPTO_ECC",
    "CRYPTO_ECDH",
)

DEPENDENCY_CONFIGS = ("USB_GADGET",)


def config_state(defconfig: Path, symbol: str) -> str | None:
    text = read(defconfig)
    pattern = re.compile(
        rf"(?m)^(?:CONFIG_{re.escape(symbol)}=([^\n]+)|# CONFIG_{re.escape(symbol)} is not set)$"
    )
    matches = pattern.findall(text)
    if len(matches) > 1:
        raise InstallError(f"defconfig contains duplicate CONFIG_{symbol} entries")
    if not matches:
        return None
    return matches[0] or "n"


def set_config(defconfig: Path, symbol: str, value: str) -> None:
    text = read(defconfig)
    pattern = re.compile(
        rf"(?m)^(?:CONFIG_{re.escape(symbol)}=[^\n]*|# CONFIG_{re.escape(symbol)} is not set)\n?"
    )
    stripped = pattern.sub("", text)
    if stripped and not stripped.endswith("\n"):
        stripped += "\n"
    if value == "n":
        line = f"# CONFIG_{symbol} is not set\n"
    else:
        line = f"CONFIG_{symbol}={value}\n"
    write(defconfig, stripped + line)


def enable_configs(defconfig: Path) -> None:
    for symbol in REQUIRED_CONFIGS:
        if config_state(defconfig, symbol) != "y":
            set_config(defconfig, symbol, "y")


def validate_defconfig(defconfig: Path, *, require_fido: bool) -> None:
    for symbol in DEPENDENCY_CONFIGS:
        if config_state(defconfig, symbol) != "y":
            raise InstallError(
                f"CONFIG_{symbol}=y is required by the FIDO gadget function"
            )
    if not require_fido:
        return
    for symbol in REQUIRED_CONFIGS:
        state = config_state(defconfig, symbol)
        if state == "m":
            raise InstallError(
                f"CONFIG_{symbol}=m is unsupported; the FIDO driver is built in"
            )
        if state != "y":
            raise InstallError(f"CONFIG_{symbol}=y is missing from {defconfig}")


def install(layout: Layout, module_root: Path, defconfig: Path | None) -> None:
    if defconfig:
        validate_defconfig(defconfig, require_fido=False)
    validate_ecc_header(layout)
    with InstallTransaction():
        copy_sources(layout, module_root)
        wire_build(layout)
        patch_configfs(layout)
        sepolicy = patch_sepolicy(layout)
    if sepolicy is None:
        print(
            "ABK FIDO Key: no KernelSU rules.c found; skipped the /metadata "
            "SELinux allow rules. Persistence may be denied by SELinux.",
            file=sys.stderr,
        )
    else:
        print(f"ABK FIDO Key: patched KernelSU sepolicy {sepolicy}")
    print(f"ABK FIDO Key: installed kernel={layout.version} root={layout.kernel_root}")


def validate_sources(layout: Layout, module_root: Path) -> None:
    """Re-run every mutation with writes disabled.

    Any write that would still change the tree means the installed state is not
    what this module version produces, so verify must fail.
    """
    global _VALIDATION_ONLY

    previous = _VALIDATION_ONLY
    _VALIDATION_ONLY = True
    try:
        copy_sources(layout, module_root)
        wire_build(layout)
        patch_configfs(layout)
        patch_sepolicy(layout)
    finally:
        _VALIDATION_ONLY = previous


def verify(layout: Layout, module_root: Path, defconfig: Path | None) -> None:
    validate_ecc_header(layout)
    validate_sources(layout, module_root)

    source = module_root / "files" / DRIVER_DIR
    for name in DRIVER_SOURCES:
        installed = layout.common / DRIVER_DIR / name
        if read(installed) != read(source / name):
            raise InstallError(f"installed source differs from module template: {installed}")
    header = layout.common / PUBLIC_HEADER
    if read(header) != read(module_root / "files" / PUBLIC_HEADER):
        raise InstallError(f"installed public header differs from module template: {header}")

    checks = {
        layout.common / "drivers/Kconfig": (KCONFIG_SOURCE_LINE,),
        layout.common / "drivers/Makefile": (MAKEFILE_OBJ_LINE,),
        layout.common / "drivers/usb/gadget/configfs.c": (
            CONFIGFS_INCLUDE,
            *CONFIGFS_MARKERS,
            "abk_fido_key_prepare_config(cdev, c, &cfg->func_list)",
            "abk_fido_key_release_config(&cfg->func_list)",
        ),
        layout.common / DRIVER_DIR / "core.c": CORE_NEEDLES,
    }
    for path, needles in checks.items():
        text = read(path)
        for needle in needles:
            if needle not in text:
                raise InstallError(f"incomplete FIDO injection: {needle!r} missing from {path}")

    core = read(layout.common / DRIVER_DIR / "core.c")
    for needle in CORE_FORBIDDEN_NEEDLES:
        if needle in core:
            raise InstallError(
                f"conflicting FIDO injection: {needle!r} present in "
                f"{layout.common / DRIVER_DIR / 'core.c'}; it would duplicate module_init"
            )

    _validate_configfs_installed(
        layout.common / "drivers/usb/gadget/configfs.c",
        read(layout.common / "drivers/usb/gadget/configfs.c"),
    )

    sepolicy = find_ksu_rules(layout)
    if sepolicy is not None and SEPOLICY_MARKER not in read(sepolicy):
        raise InstallError(f"ABK FIDO sepolicy allow rules missing from {sepolicy}")

    if defconfig:
        validate_defconfig(defconfig, require_fido=True)

    sepolicy_state = "absent" if sepolicy is None else str(sepolicy)
    print(
        f"ABK FIDO Key: verified kernel={layout.version} "
        f"ecc_header={ECC_HEADER_BY_LINE[layout.version]} sepolicy={sepolicy_state}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("install", "verify", "detect", "enable-config"))
    parser.add_argument("--kernel-root", required=True, type=Path)
    parser.add_argument("--module-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--defconfig", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        layout = discover(args.kernel_root.resolve())
        if args.command == "detect":
            validate_ecc_header(layout)
            print(
                f"kernel={layout.version} common={layout.common} "
                f"ecc_header={ECC_HEADER_BY_LINE[layout.version]} "
                f"ksu={find_ksu_rules(layout) or 'absent'}"
            )
        elif args.command == "install":
            install(layout, args.module_root.resolve(), args.defconfig)
        elif args.command == "enable-config":
            if not args.defconfig:
                raise InstallError("enable-config requires --defconfig")
            enable_configs(args.defconfig)
        else:
            verify(layout, args.module_root.resolve(), args.defconfig)
        return 0
    except InstallError as exc:
        print(f"ABK FIDO Key: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
