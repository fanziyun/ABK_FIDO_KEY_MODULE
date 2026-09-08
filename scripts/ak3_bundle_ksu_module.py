#!/usr/bin/env python3
"""Bundle the KernelSU SELinux module into an AnyKernel3 zip.

Flashing a kernel and flashing the SELinux module are one action for the user:
if the module is missing, the driver's persist fails with -13 and the app shows
no registered keys. So the module rides inside the AnyKernel3 zip instead of
being a second download:

* the module zip is stored at ``abk-ksu-modules/<module id>.zip`` in the AK3
  tree, which the AK3 installer unzips into ``$AKHOME``;
* an idempotent installer block is appended to ``anykernel.sh``. AK3 runs
  ``anykernel.sh`` after writing the boot image, so the block installs the
  module through ``ksud``/``magisk`` and falls back to unpacking the module into
  ``/data/adb/modules/<id>`` when neither is usable (for example in recovery).

Both halves are additive: no AK3 file is removed and no property of the upstream
``anykernel.sh`` changes. The block is delimited by markers, so re-running the
injector replaces it instead of stacking copies.

The ABK build hook calls this automatically (see ``scripts/abk_fido_setup.sh``);
the same CLI also patches a finished zip by hand:

    python3 scripts/ak3_bundle_ksu_module.py inject \\
        --zip Android15-6.6.98-AnyKernel3.zip --output AK3-with-abk-fido.zip
    python3 scripts/ak3_bundle_ksu_module.py verify --zip AK3-with-abk-fido.zip
"""

from __future__ import annotations

import argparse
import io
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
REPOSITORY = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

from build_ksu_module import MODULE_SOURCE, build as build_module  # noqa: E402

ANY_KERNEL_SCRIPT = "anykernel.sh"
BUNDLE_DIR = "abk-ksu-modules"
BEGIN_MARKER = "### >>> ABK FIDO KernelSU module installer"
END_MARKER = "### <<< ABK FIDO KernelSU module installer"

REGULAR_MODE = 0o644
EXECUTABLE_MODE = 0o755

INSTALLER_BLOCK = f"""\
{BEGIN_MARKER} (managed by ABK_FIDO_KEY_MODULE) >>>
## Installs the SELinux rules module shipped in {BUNDLE_DIR}/, so that flashing
## this AnyKernel3 zip also installs the KernelSU module the driver needs for
## /metadata persistence. Additive and non-fatal: the boot image is already
## written when this runs, so a failure only prints a warning.
if ! command -v ui_print >/dev/null 2>&1; then
  ui_print() {{ echo "$@"; }}
fi

abk_fido_install_ksu_modules() {{
  ABK_FIDO_HOME="${{AKHOME:-$PWD}}"
  ABK_FIDO_SRC="$ABK_FIDO_HOME/{BUNDLE_DIR}"
  [ -d "$ABK_FIDO_SRC" ] || return 0
  ABK_FIDO_UNZIP="unzip"
  [ -x "$ABK_FIDO_HOME/tools/busybox" ] && ABK_FIDO_UNZIP="$ABK_FIDO_HOME/tools/busybox unzip"
  for ABK_FIDO_ZIP in "$ABK_FIDO_SRC"/*.zip; do
    [ -f "$ABK_FIDO_ZIP" ] || continue
    ABK_FIDO_ID="$(basename "$ABK_FIDO_ZIP" .zip)"
    ABK_FIDO_VIA=""
    for ABK_FIDO_KSUD in /data/adb/ksud /data/adb/ksu/bin/ksud /data/adb/ap/bin/apd; do
      [ -x "$ABK_FIDO_KSUD" ] || continue
      if "$ABK_FIDO_KSUD" module install "$ABK_FIDO_ZIP" >/dev/null 2>&1; then
        ABK_FIDO_VIA="$(basename "$ABK_FIDO_KSUD")"
        break
      fi
    done
    if [ -z "$ABK_FIDO_VIA" ] && command -v magisk >/dev/null 2>&1; then
      magisk --install-module "$ABK_FIDO_ZIP" >/dev/null 2>&1 && ABK_FIDO_VIA="magisk"
    fi
    if [ -z "$ABK_FIDO_VIA" ] && [ -d /data/adb ]; then
      ABK_FIDO_TARGET="/data/adb/modules/$ABK_FIDO_ID"
      rm -rf "$ABK_FIDO_TARGET"
      mkdir -p "$ABK_FIDO_TARGET" 2>/dev/null
      if $ABK_FIDO_UNZIP -o "$ABK_FIDO_ZIP" -d "$ABK_FIDO_TARGET" >/dev/null 2>&1; then
        chmod 0755 "$ABK_FIDO_TARGET"/*.sh 2>/dev/null
        if command -v chcon >/dev/null 2>&1; then
          chcon -R u:object_r:system_file:s0 "$ABK_FIDO_TARGET" 2>/dev/null
        fi
        ABK_FIDO_VIA="unpacked to /data/adb/modules"
      fi
    fi
    if [ -n "$ABK_FIDO_VIA" ]; then
      ui_print "  -> ABK FIDO: KernelSU module $ABK_FIDO_ID installed via $ABK_FIDO_VIA"
    else
      ui_print "  -> ABK FIDO: WARNING could not install $ABK_FIDO_ID, flash abk_fido_selinux.zip manually"
    fi
  done
  return 0
}}

abk_fido_install_ksu_modules || ui_print "  -> ABK FIDO: KernelSU module step skipped"
unset ABK_FIDO_HOME ABK_FIDO_SRC ABK_FIDO_UNZIP ABK_FIDO_ZIP ABK_FIDO_ID ABK_FIDO_VIA \\
  ABK_FIDO_KSUD ABK_FIDO_TARGET 2>/dev/null
{END_MARKER} <<<
"""

_BLOCK_PATTERN = re.compile(
    re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER) + r" <<<",
    re.DOTALL,
)


class InjectionError(SystemExit):
    """A condition the caller must fix; the CLI reports it and exits non-zero."""


def module_id(source: Path = MODULE_SOURCE) -> str:
    """The `id=` of module.prop, which is also the module directory name."""
    prop = source / "module.prop"
    if prop.is_file():
        for line in prop.read_text(encoding="utf-8").splitlines():
            if line.startswith("id="):
                return line[3:].strip()
    raise InjectionError(f"no id= in {prop}")


def module_zip_id(module_zip: Path) -> str:
    """The module id inside a built zip; KernelSU names the directory after it.

    Reading it from the archive rather than from the file name means a caller can
    pass a zip named anything (a CI temp file, a downloaded release asset) and
    still get ``<id>.zip`` in the AK3 bundle.
    """
    with zipfile.ZipFile(module_zip) as archive:
        if "module.prop" not in archive.namelist():
            raise InjectionError(f"{module_zip} has no module.prop")
        for line in archive.read("module.prop").decode("utf-8").splitlines():
            if line.startswith("id="):
                return line[3:].strip()
    raise InjectionError(f"no id= in {module_zip}:module.prop")


def build_module_zip(source: Path = MODULE_SOURCE, output: Path | None = None) -> Path:
    """Build the module zip; without an explicit output it lands in a temp dir."""
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="abk-fido-ksu-")) / f"{module_id(source)}.zip"
    return build_module(source, output)


def inject_script(text: str) -> str:
    """Append the installer block, or replace an existing one in place.

    Line endings are normalised to LF first: the device sources this script with
    ``ash``, where a trailing ``\\r`` becomes part of the last token. A Windows
    checkout (``core.autocrlf``) is the usual way a CRLF ``anykernel.sh`` reaches
    the injector, and the block must never be appended to a script that cannot
    run.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if _BLOCK_PATTERN.search(text):
        return _BLOCK_PATTERN.sub(lambda _: INSTALLER_BLOCK.rstrip("\n"), text)
    separator = "" if text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
    return f"{text}{separator}{INSTALLER_BLOCK}"


def discover_ak3_dir(hint: str | None = None, start: Path | None = None) -> Path | None:
    """Locate an extracted AnyKernel3 tree without relying on ABK's env names."""
    candidates: list[Path] = []
    if hint:
        candidates.append(Path(hint))
    for value in (os.environ.get("ANYKERNEL3"), os.environ.get("GITHUB_WORKSPACE")):
        if not value:
            continue
        root = Path(value)
        candidates.extend([root, root / "AnyKernel3", root / "oneplus_workspace/AnyKernel3"])

    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace and Path(workspace).is_dir():
        root = Path(workspace)
        for pattern in ("*/anykernel.sh", "*/*/anykernel.sh"):
            candidates.extend(path.parent for path in sorted(root.glob(pattern)))

    origin = (start or Path.cwd()).resolve()
    # Bounded walk: ABK's module checkout sits next to AnyKernel3, so two levels
    # are enough. Never climb to a drive root, where globbing can be enormous.
    for parent in [origin, *origin.parents[:2]]:
        candidates.append(parent)
        candidates.extend(path.parent for path in sorted(parent.glob("*/anykernel.sh")))

    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:  # pragma: no cover - unreadable candidate
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if (resolved / ANY_KERNEL_SCRIPT).is_file() and (resolved / "tools").is_dir():
            return resolved
    return None


def inject_dir(ak3_dir: Path, module_zip: Path) -> tuple[Path, Path]:
    """Patch an extracted AnyKernel3 tree in place."""
    script = ak3_dir / ANY_KERNEL_SCRIPT
    if not script.is_file():
        raise InjectionError(f"no {ANY_KERNEL_SCRIPT} in {ak3_dir}")
    if not module_zip.is_file():
        raise InjectionError(f"module zip not found: {module_zip}")

    bundle = ak3_dir / BUNDLE_DIR
    bundle.mkdir(parents=True, exist_ok=True)
    target = bundle / f"{module_zip_id(module_zip)}.zip"
    target.write_bytes(module_zip.read_bytes())

    # write_bytes, not write_text: text mode would turn the LF endings back into
    # CRLF on Windows and hand the device an unparsable script.
    script.write_bytes(inject_script(script.read_text(encoding="utf-8")).encode("utf-8"))
    script.chmod(script.stat().st_mode | 0o111)
    return script, target


def _zip_info(name: str, mode: int, date_time: tuple[int, int, int, int, int, int]) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=date_time)
    info.create_system = 3  # unix, so external_attr carries the mode
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def inject_zip(source: Path, output: Path, module_zip: Path) -> tuple[Path, str]:
    """Rewrite an AnyKernel3 zip with the module and the installer block added."""
    if not source.is_file():
        raise InjectionError(f"ak3 zip not found: {source}")

    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        if ANY_KERNEL_SCRIPT not in names:
            raise InjectionError(f"{source} has no {ANY_KERNEL_SCRIPT} at the zip root")
        patched = inject_script(archive.read(ANY_KERNEL_SCRIPT).decode("utf-8")).encode("utf-8")
        script_mode = (archive.getinfo(ANY_KERNEL_SCRIPT).external_attr >> 16) & 0o777

    module_name = f"{BUNDLE_DIR}/{module_zip_id(module_zip)}.zip"
    module_bytes = module_zip.read_bytes()

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source) as archive, zipfile.ZipFile(output, "w") as target:
        for info in archive.infolist():
            if info.filename == ANY_KERNEL_SCRIPT:
                data = patched
            elif info.filename == module_name:
                data = module_bytes
            else:
                data = archive.read(info.filename)
            if info.is_dir():
                new_info = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                new_info.create_system = info.create_system
                new_info.external_attr = info.external_attr
                new_info.compress_type = zipfile.ZIP_STORED
            else:
                new_info = _zip_info(
                    info.filename,
                    (info.external_attr >> 16) & 0o777 or script_mode,
                    info.date_time,
                )
                new_info.create_system = info.create_system
            target.writestr(new_info, data)
        if module_name not in names:
            target.writestr(
                _zip_info(module_name, REGULAR_MODE, (1980, 1, 1, 0, 0, 0)), module_bytes
            )
    return output, module_name


def _check_anykernel_text(text: str, problems: list[str]) -> None:
    if text.count(BEGIN_MARKER) != 1 or text.count(END_MARKER) != 1:
        problems.append("anykernel.sh must contain exactly one installer block")
        return
    block = _BLOCK_PATTERN.search(text)
    assert block is not None
    body = block.group(0)
    for needle in ("module install", "magisk --install-module", "/data/adb/modules/"):
        if needle not in body:
            problems.append(f"installer block is missing {needle!r}")
    if "\nset -e" in body:
        problems.append("installer block must not enable set -e")
    if re.search(r"^\s*exit\s+[1-9]", body, re.MULTILINE):
        problems.append("installer block must not abort the flash")


def _check_module_zip(data: bytes, expected_name: str, problems: list[str]) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            if "module.prop" not in names:
                problems.append("bundled module zip has no module.prop")
                return
            props = {}
            for line in archive.read("module.prop").decode("utf-8").splitlines():
                if "=" in line and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    props[key.strip()] = value.strip()
            if props.get("id") != expected_name:
                problems.append(
                    f"bundled module id {props.get('id')!r} does not match entry name {expected_name!r}"
                )
            for info in archive.infolist():
                if info.filename.endswith(".sh"):
                    mode = (info.external_attr >> 16) & 0o777
                    if mode != EXECUTABLE_MODE:
                        problems.append(
                            f"{info.filename} must be 0755 in the module zip, got {oct(mode)}"
                        )
    except zipfile.BadZipFile:
        problems.append("bundled module zip is not a readable zip")


def _check_bundle_files(pairs: list[tuple[str, bytes]], script_text: str) -> list[str]:
    problems: list[str] = []
    _check_anykernel_text(script_text, problems)
    modules = [
        (name, data)
        for name, data in pairs
        if name.startswith(f"{BUNDLE_DIR}/") and not name.endswith("/")
    ]
    if not modules:
        problems.append(f"no module zip under {BUNDLE_DIR}/")
    for name, data in modules:
        _check_module_zip(data, Path(name).stem, problems)
    return problems


def verify_dir(ak3_dir: Path) -> list[str]:
    script = ak3_dir / ANY_KERNEL_SCRIPT
    if not script.is_file():
        return [f"no {ANY_KERNEL_SCRIPT} in {ak3_dir}"]
    bundle = ak3_dir / BUNDLE_DIR
    pairs = [(f"{BUNDLE_DIR}/{path.name}", path.read_bytes()) for path in sorted(bundle.glob("*.zip"))]
    return _check_bundle_files(pairs, script.read_text(encoding="utf-8"))


def verify_zip(source: Path) -> list[str]:
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        if ANY_KERNEL_SCRIPT not in names:
            return [f"{source} has no {ANY_KERNEL_SCRIPT} at the zip root"]
        # `zip -r` stores directory entries too; only files can be module zips.
        pairs = [
            (name, archive.read(name))
            for name in names
            if name.startswith(f"{BUNDLE_DIR}/") and not name.endswith("/")
        ]
        script_text = archive.read(ANY_KERNEL_SCRIPT).decode("utf-8")
    problems = _check_bundle_files(pairs, script_text)
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_targets(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "--ak3-dir",
            default=None,
            help="extracted AnyKernel3 tree, or 'auto' to discover it (default: auto)",
        )
        target.add_argument("--zip", type=Path, default=None, help="finished AnyKernel3 zip")

    inject = subparsers.add_parser("inject", help="add the module and the installer block")
    add_targets(inject)
    inject.add_argument("--output", type=Path, default=None, help="output zip (required with --zip)")
    inject.add_argument("--source", type=Path, default=MODULE_SOURCE, help="KernelSU module source dir")
    inject.add_argument("--module-zip", type=Path, default=None, help="prebuilt module zip to embed")
    inject.add_argument(
        "--strict",
        action="store_true",
        help="fail when no AnyKernel3 tree can be found instead of warning",
    )

    verify = subparsers.add_parser("verify", help="check that a bundle is complete and runnable")
    add_targets(verify)

    args = parser.parse_args(argv)

    module_zip = getattr(args, "module_zip", None)
    if module_zip is None:
        module_zip = build_module_zip(getattr(args, "source", MODULE_SOURCE))

    if args.zip is not None:
        if args.command == "inject":
            if args.output is None:
                raise InjectionError("--output is required with --zip")
            output, entry = inject_zip(args.zip, args.output, module_zip)
            print(f"injected {entry} into {output}")
            problems = verify_zip(output)
        else:
            problems = verify_zip(args.zip)
    else:
        hint = None if args.ak3_dir in (None, "auto") else args.ak3_dir
        ak3_dir = discover_ak3_dir(hint)
        if ak3_dir is None:
            message = "no extracted AnyKernel3 tree found (looked for anykernel.sh + tools/)"
            if getattr(args, "strict", False):
                raise InjectionError(message)
            print(f"warning: {message}; nothing to bundle", file=sys.stderr)
            return 0
        if args.command == "inject":
            script, target = inject_dir(ak3_dir, module_zip)
            print(f"injected {BUNDLE_DIR}/{target.name} and the installer block into {script}")
            problems = verify_dir(ak3_dir)
        else:
            problems = verify_dir(ak3_dir)

    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print(f"ok: {module_id()} is bundled and its installer block is present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
