#!/usr/bin/env python3
"""Pin the KernelSU SELinux module to the access the driver actually needs.

The module exists because of one measured failure on an enforcing device: the
driver opens /metadata/abk_fido_store.bin from the kernel domain and SELinux
answers

    avc: denied { write } for comm="kworker/1:0" name="abk_fido_store.bin"
      scontext=u:r:kernel:s0 tcontext=u:object_r:metadata_file:s0 tclass=file
    avc: denied { read } for ... scontext=u:r:kernel:s0 ...
      tcontext=u:object_r:metadata_file:s0 tclass=file

so persist fails with -13 and the app's key list stays empty. None of that can
be executed on the host, so the rules are pinned here against the driver's
source and against the compiled-in KernelSU path that does the same job.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
MODULE = REPOSITORY / "ksu/abk_fido_selinux"
MODULE_PROP = MODULE / "module.prop"
SEPOLICY = MODULE / "sepolicy.rule"
POST_FS_DATA = MODULE / "post-fs-data.sh"
DRIVER = REPOSITORY / "files/drivers/abk_fido_key/core.c"
KERNELSU_PATCH = REPOSITORY / "scripts/patch_kernelsu_sepolicy_for_abk_fido.py"

STORE_PATH = "/metadata/abk_fido_store.bin"

# (source, target, class, required permissions)
REQUIRED_RULES = (
    ("kernel", "metadata_file", "dir", {"search"}),
    ("kernel", "metadata_file", "file", {"open", "read", "write", "getattr"}),
)

_RULE = re.compile(
    r"^allow\s+(\S+)\s+(\S+)\s+(\S+)\s+\{\s*([^}]*?)\s*\}\s*$",
    re.MULTILINE,
)


def parse_rules(text: str) -> dict[tuple[str, str, str], set[str]]:
    """`allow src tgt class { perms }` lines, whitespace-normalised."""
    rules: dict[tuple[str, str, str], set[str]] = {}
    for match in _RULE.finditer(text):
        source, target, target_class, permissions = match.groups()
        key = (source, target, target_class)
        rules.setdefault(key, set()).update(permissions.split())
    return rules


class ModuleMetadataTest(unittest.TestCase):
    def test_id_matches_the_directory_kernelsu_installs_into(self) -> None:
        # KernelSU names the module directory after the zip, and ksud reads the
        # id from module.prop; a mismatch silently installs under the wrong name.
        props = {}
        for line in MODULE_PROP.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                props[key.strip()] = value.strip()
        self.assertEqual("abk_fido_selinux", props.get("id"))
        self.assertEqual(MODULE.name, props["id"])
        for key in ("name", "version", "versionCode", "author", "description"):
            self.assertTrue(props.get(key), f"module.prop is missing {key}")
        self.assertGreater(int(props["versionCode"]), 0)


class SepolicyRuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = parse_rules(SEPOLICY.read_text(encoding="utf-8"))

    def test_grants_every_permission_the_avc_denials_named(self) -> None:
        for source, target, target_class, required in REQUIRED_RULES:
            granted = self.rules.get((source, target, target_class), set())
            self.assertTrue(
                required <= granted,
                f"{source} -> {target}:{target_class} grants {sorted(granted)}, "
                f"needs at least {sorted(required)}",
            )

    def test_only_the_kernel_domain_is_widened(self) -> None:
        # The app's root shell already writes /metadata and the sysfs nodes on
        # this device, so widening su/magisk/ksu here would be an unmeasured
        # grant. Keep the module to the domain the AVC named.
        sources = {source for source, _, _ in self.rules}
        self.assertEqual({"kernel"}, sources)

    def test_never_switches_selinux_off(self) -> None:
        # Comments may say the rules stay enforce-safe; no executable line may
        # turn the policy permissive.
        for path in (SEPOLICY, POST_FS_DATA):
            lines = [
                line.split("#", 1)[0]
                for line in path.read_text(encoding="utf-8").splitlines()
            ]
            body = "\n".join(lines)
            self.assertNotIn("permissive", body, path.name)
            self.assertNotIn("setenforce", body, path.name)


class PostFsDataTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = POST_FS_DATA.read_text(encoding="utf-8")

    def test_reapplies_the_same_rules_as_a_fallback(self) -> None:
        # sepolicy.rule is the primary path; the script covers a KernelSU build
        # that does not auto-apply it.
        self.assertIn("sepolicy apply", self.script)
        self.assertIn("sepolicy.rule", self.script)

    def test_precreates_the_store_file(self) -> None:
        # The driver's persist is O_WRONLY|O_CREAT|O_TRUNC; pre-creating keeps
        # the common path at file open/write instead of relying on the dir grant.
        self.assertIn(STORE_PATH, self.script)
        self.assertIn("chmod 0600", self.script)
        self.assertIn("restorecon", self.script)


class DriverContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.driver = DRIVER.read_text(encoding="utf-8")

    def test_driver_opens_the_store_as_the_kernel_domain(self) -> None:
        # prepare_kernel_cred(NULL) is why the rules must name `kernel`.
        self.assertIn("prepare_kernel_cred(NULL)", self.driver)

    def test_module_path_matches_the_driver_store_path(self) -> None:
        self.assertIn(f'ABK_FIDO_STORE_PATH\t\t\t"{STORE_PATH}"', self.driver)
        self.assertIn(STORE_PATH, POST_FS_DATA.read_text(encoding="utf-8"))

    def test_driver_persist_uses_create_and_truncate(self) -> None:
        # Pins the flags the rule set was derived from.
        self.assertIn("O_WRONLY | O_CREAT | O_TRUNC", self.driver)


class CompiledInPatchTest(unittest.TestCase):
    def test_both_kernelsu_paths_grant_the_same_permissions(self) -> None:
        # The build-time rules.c patch and this module solve the same problem;
        # if one gains a permission the other must not be left behind.
        patch = KERNELSU_PATCH.read_text(encoding="utf-8")
        granted = {
            permission
            for permission in ("create", "open", "read", "write", "getattr", "search")
            if f'ksu_allow(db, "kernel", "metadata_file", "dir", "{permission}")' in patch
            or f'ksu_allow(db, "kernel", "metadata_file", "file", "{permission}")' in patch
        }
        module = parse_rules(SEPOLICY.read_text(encoding="utf-8"))
        module_granted = set()
        for (source, target, _), permissions in module.items():
            if source == "kernel" and target == "metadata_file":
                module_granted |= permissions
        self.assertTrue(
            {"read", "write"} <= granted,
            f"compiled-in patch lost the AVC-named permissions: {sorted(granted)}",
        )
        self.assertEqual(
            module_granted - {"add_name"},
            granted,
            "module and compiled-in KernelSU rules drifted apart",
        )


if __name__ == "__main__":
    unittest.main()
