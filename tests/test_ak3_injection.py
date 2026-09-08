#!/usr/bin/env python3
"""Pin the AnyKernel3 bundling of the KernelSU SELinux module.

The module only helps if it is installed by the same flash that writes the boot
image. These tests run the real injector against a synthetic AnyKernel3 tree and
zip, so a regression that drops the block, ships the wrong module, loses a zip
entry or turns the installer into a fatal step fails here instead of on a phone
that then shows no registered keys.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "scripts"))

import ak3_bundle_ksu_module as bundle  # noqa: E402

UPSTREAM_ANY_KERNEL = """\
### AnyKernel3 Ramdisk Mod Script
## osm0sis @ xda-developers

properties() { '
kernel.string=ABK Kernel
do.devicecheck=0
do.modules=0
do.systemless=0
do.cleanup=1
'; } # end properties

block=boot
is_slot_device=auto
no_magisk_check=1

. tools/ak3-core.sh

split_boot
if [ -f "$SPLITIMG/ramdisk.cpio" ]; then
    unpack_ramdisk
    write_boot
else
    flash_boot
fi
"""


def write_ak3_tree(root: Path, script: str = UPSTREAM_ANY_KERNEL) -> Path:
    (root / "tools").mkdir(parents=True, exist_ok=True)
    (root / "META-INF/com/google/android").mkdir(parents=True, exist_ok=True)
    (root / "tools/ak3-core.sh").write_text("# stub core\n", encoding="utf-8")
    (root / "tools/busybox").write_bytes(b"\x7fELF stub")
    (root / "META-INF/com/google/android/update-binary").write_text("# stub\n", encoding="utf-8")
    (root / "anykernel.sh").write_text(script, encoding="utf-8")
    (root / "anykernel.sh").chmod(0o755)
    (root / "Image").write_bytes(b"kernel-image")
    return root


def zip_ak3_tree(root: Path, target: Path) -> Path:
    # Modes are set explicitly: on Windows chmod only toggles the read-only bit,
    # so st_mode would report 0o666 and the mode-preservation check would be
    # meaningless.
    modes = {
        "anykernel.sh": 0o755,
        "tools/busybox": 0o755,
        "META-INF/com/google/android/update-binary": 0o755,
    }
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_dir():
                continue
            relative = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(2024, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = modes.get(relative, 0o644) << 16
            archive.writestr(info, path.read_bytes())
    return target


class InjectScriptTest(unittest.TestCase):
    def test_appends_the_block_once_and_keeps_the_upstream_script(self) -> None:
        patched = bundle.inject_script(UPSTREAM_ANY_KERNEL)
        self.assertTrue(patched.startswith(UPSTREAM_ANY_KERNEL.rstrip("\n")))
        self.assertEqual(1, patched.count(bundle.BEGIN_MARKER))
        self.assertEqual(1, patched.count(bundle.END_MARKER))

    def test_reinjection_replaces_the_block_instead_of_stacking(self) -> None:
        once = bundle.inject_script(UPSTREAM_ANY_KERNEL)
        twice = bundle.inject_script(once)
        self.assertEqual(once, twice)
        self.assertEqual(1, twice.count(bundle.BEGIN_MARKER))

    def test_a_script_without_a_trailing_newline_still_parses(self) -> None:
        patched = bundle.inject_script(UPSTREAM_ANY_KERNEL.rstrip("\n"))
        self.assertEqual(1, patched.count(bundle.BEGIN_MARKER))
        self.assertIn("\n" + bundle.BEGIN_MARKER, patched)

    def test_crlf_input_is_normalised_to_lf(self) -> None:
        # ash on the device treats the trailing \r as part of the token, so a
        # CRLF anykernel.sh would not run at all.
        patched = bundle.inject_script(UPSTREAM_ANY_KERNEL.replace("\n", "\r\n"))
        self.assertNotIn("\r", patched)
        self.assertEqual(1, patched.count(bundle.BEGIN_MARKER))

    def test_block_installs_ksud_first_then_magisk_then_unpacks(self) -> None:
        # Order matters: ksud owns the KernelSU module layout, magisk covers
        # Magisk, and the direct unpack is the recovery fallback.
        block = bundle.INSTALLER_BLOCK
        positions = [
            block.index("/data/adb/ksu/bin/ksud"),
            block.index("magisk --install-module"),
            block.index('ABK_FIDO_TARGET="/data/adb/modules/$ABK_FIDO_ID"'),
        ]
        self.assertEqual(positions, sorted(positions))

    def test_block_never_turns_the_flash_into_a_failure(self) -> None:
        block = bundle.INSTALLER_BLOCK
        self.assertNotIn("\nset -e", block)
        self.assertIsNone(re.search(r"^\s*exit\s+[1-9]", block, re.MULTILINE))
        self.assertIn("abk_fido_install_ksu_modules || ui_print", block)

    def test_block_is_valid_posix_shell(self) -> None:
        shell = shutil.which("sh") or shutil.which("bash") or shutil.which("dash")
        if shell is None:
            self.skipTest("no POSIX shell available to syntax-check the block")
        # Feed the block on stdin: Git-for-Windows' sh mangles native paths, and
        # bytes keep text mode from rewriting newlines into CRLF.
        result = subprocess.run(
            [shell, "-n"],
            input=bundle.INSTALLER_BLOCK.encode("utf-8"),
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8", "replace"))


class InjectTreeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "AnyKernel3"
        write_ak3_tree(self.root)
        self.module_zip = bundle.build_module_zip(output=Path(self.tmp.name) / f"{bundle.module_id()}.zip")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_injects_the_module_and_the_block(self) -> None:
        script, target = bundle.inject_dir(self.root, self.module_zip)
        self.assertTrue(target.is_file())
        self.assertEqual(f"{bundle.module_id()}.zip", target.name)
        self.assertTrue(os.access(script, os.X_OK), "anykernel.sh must stay executable")
        self.assertEqual([], bundle.verify_dir(self.root))

    def test_injected_script_still_starts_with_the_upstream_body(self) -> None:
        bundle.inject_dir(self.root, self.module_zip)
        self.assertTrue(
            (self.root / "anykernel.sh").read_text(encoding="utf-8").startswith(UPSTREAM_ANY_KERNEL)
        )

    def test_injected_script_is_lf_on_disk(self) -> None:
        # read_text hides a CRLF regression through universal newlines, so read
        # the bytes: the device's ash would choke on every \r.
        bundle.inject_dir(self.root, self.module_zip)
        self.assertNotIn(b"\r", (self.root / "anykernel.sh").read_bytes())

    def test_verify_reports_a_missing_bundle(self) -> None:
        bundle.inject_dir(self.root, self.module_zip)
        for path in (self.root / bundle.BUNDLE_DIR).glob("*.zip"):
            path.unlink()
        problems = bundle.verify_dir(self.root)
        self.assertTrue(any("no module zip" in problem for problem in problems), problems)

    def test_verify_reports_a_missing_block(self) -> None:
        (self.root / bundle.BUNDLE_DIR).mkdir()
        (self.root / bundle.BUNDLE_DIR / f"{bundle.module_id()}.zip").write_bytes(
            self.module_zip.read_bytes()
        )
        problems = bundle.verify_dir(self.root)
        self.assertTrue(any("installer block" in problem for problem in problems), problems)


class InjectZipTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name) / "AnyKernel3"
        write_ak3_tree(root)
        self.source = zip_ak3_tree(root, Path(self.tmp.name) / "AnyKernel3.zip")
        self.output = Path(self.tmp.name) / "AnyKernel3-abk.zip"
        self.module_zip = bundle.build_module_zip(output=Path(self.tmp.name) / f"{bundle.module_id()}.zip")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_keeps_every_upstream_entry_and_its_mode(self) -> None:
        with zipfile.ZipFile(self.source) as archive:
            before = {info.filename: (info.external_attr >> 16) & 0o777 for info in archive.infolist()}
        bundle.inject_zip(self.source, self.output, self.module_zip)
        with zipfile.ZipFile(self.output) as archive:
            after = {info.filename: (info.external_attr >> 16) & 0o777 for info in archive.infolist()}
        for name, mode in before.items():
            self.assertIn(name, after, f"{name} disappeared from the AK3 zip")
            self.assertEqual(mode, after[name], f"{name} changed mode")
        self.assertEqual(0o755, after["anykernel.sh"])
        self.assertIn(f"{bundle.BUNDLE_DIR}/{bundle.module_id()}.zip", after)

    def test_the_source_zip_is_not_modified_in_place(self) -> None:
        with zipfile.ZipFile(self.source) as archive:
            original = archive.read("anykernel.sh")
        bundle.inject_zip(self.source, self.output, self.module_zip)
        with zipfile.ZipFile(self.source) as archive:
            self.assertEqual(original, archive.read("anykernel.sh"))

    def test_verify_accepts_the_injected_zip(self) -> None:
        bundle.inject_zip(self.source, self.output, self.module_zip)
        self.assertEqual([], bundle.verify_zip(self.output))

    def test_verify_rejects_a_zip_without_the_module(self) -> None:
        problems = bundle.verify_zip(self.source)
        self.assertTrue(any("no module zip" in problem for problem in problems), problems)

    def test_verify_tolerates_zip_directory_entries(self) -> None:
        # ABK builds the AK3 zip with `zip -r ./*`, which stores directory
        # entries; an empty abk-ksu-modules/ entry must not read as a broken zip.
        bundle.inject_zip(self.source, self.output, self.module_zip)
        with_dir_entry = Path(self.tmp.name) / "with-dir-entry.zip"
        with zipfile.ZipFile(self.output) as src, zipfile.ZipFile(with_dir_entry, "w") as dst:
            dst.writestr(f"{bundle.BUNDLE_DIR}/", b"")
            for info in src.infolist():
                dst.writestr(info, src.read(info.filename))
        self.assertEqual([], bundle.verify_zip(with_dir_entry))

    def test_reinjection_into_an_already_patched_zip_is_idempotent(self) -> None:
        bundle.inject_zip(self.source, self.output, self.module_zip)
        second = Path(self.tmp.name) / "AnyKernel3-abk-2.zip"
        bundle.inject_zip(self.output, second, self.module_zip)
        with zipfile.ZipFile(second) as archive:
            script = archive.read("anykernel.sh").decode("utf-8")
            names = archive.namelist()
        self.assertEqual(1, script.count(bundle.BEGIN_MARKER))
        self.assertEqual(1, names.count(f"{bundle.BUNDLE_DIR}/{bundle.module_id()}.zip"))


class DiscoverTest(unittest.TestCase):
    def test_finds_the_tree_next_to_the_module_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            write_ak3_tree(workspace / "AnyKernel3")
            checkout = workspace / "custom_external_module_01-ABK_FIDO_KEY_MODULE"
            checkout.mkdir()
            env = {"GITHUB_WORKSPACE": str(workspace), "ANYKERNEL3": str(workspace / "AnyKernel3")}
            with mock.patch.dict(os.environ, env, clear=False):
                found = bundle.discover_ak3_dir(start=checkout)
            self.assertEqual((workspace / "AnyKernel3").resolve(), found)

    def test_returns_none_when_there_is_no_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Nested deep enough that the discovery walk never reaches the temp
            # root, where unrelated checkouts may live.
            empty = Path(tmp)
            checkout = empty / "a/b/c"
            checkout.mkdir(parents=True)
            env = {"GITHUB_WORKSPACE": str(empty)}
            with mock.patch.dict(os.environ, env, clear=False):
                os.environ.pop("ANYKERNEL3", None)
                self.assertIsNone(bundle.discover_ak3_dir(start=checkout))


class SetupHookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.setup_sh = (REPOSITORY / "setup.sh").read_text(encoding="utf-8")
        cls.functions = (REPOSITORY / "scripts/abk_fido_setup.sh").read_text(encoding="utf-8")

    def test_both_stages_bundle_the_module(self) -> None:
        # after_patch and before_build both run in ABK's build, so the hook has
        # to be idempotent and present in both branches.
        self.assertEqual(2, self.setup_sh.count("abk_fido_bundle_ksu_module_into_ak3"))

    def test_hook_uses_auto_discovery_and_verifies(self) -> None:
        self.assertIn("ak3_bundle_ksu_module.py\" inject --ak3-dir auto", self.functions)
        self.assertIn("ak3_bundle_ksu_module.py\" verify --ak3-dir auto", self.functions)

    def test_hook_fails_loudly_when_the_tree_is_there_but_injection_fails(self) -> None:
        self.assertIn("abk_die", self.functions.split("abk_fido_bundle_ksu_module_into_ak3()")[1])


class ReadmeTest(unittest.TestCase):
    def test_documents_the_bundled_ak3_flow(self) -> None:
        readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")
        self.assertIn("abk-ksu-modules", readme)
        self.assertIn("ak3_bundle_ksu_module.py", readme)


if __name__ == "__main__":
    unittest.main()
