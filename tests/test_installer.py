#!/usr/bin/env python3
"""Black-box tests for the FIDO source installer.

The fixtures model only the source anchors owned by install.py. They are not
kernel compilation fixtures: a passing run says the installer wires and verifies
the tree it is given, not that the resulting kernel builds or boots.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
INSTALLER = REPOSITORY / "scripts/install.py"
SETUP = REPOSITORY / "setup.sh"

MARKER = "ABK_FIDO_KEY_V1"


def _load_installer() -> object:
    """Import install.py as a module so its needle tables can be reused."""
    name = "abk_fido_installer"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(name, INSTALLER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves annotations through sys.modules, so register before
    # executing rather than after.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


# Mirrors the shape of drivers/usb/gadget/configfs.c that the installer anchors
# on. Verified byte-identical in android13-5.15-lts and android14-6.1-lts for
# all three anchors.
CONFIGFS = """\
// SPDX-License-Identifier: GPL-2.0
#include <linux/usb/composite.h>
#include "configfs.h"
#include "u_f.h"
#include "u_os_desc.h"

static void gadget_config_attr_release(struct config_item *item)
{
\tstruct config_usb_cfg *cfg = to_config_usb_cfg(item);

\tWARN_ON(!list_empty(&cfg->c.functions));
\tlist_del(&cfg->c.list);
\tkfree(cfg->c.label);
\tkfree(cfg);
}

static int configfs_composite_bind(struct usb_gadget *gadget,
\t\tstruct usb_gadget_driver *gdriver)
{
\tstruct usb_composite_driver *composite = to_cdriver(gdriver);
\tstruct gadget_info *gi = container_of(composite, struct gadget_info, composite);
\tstruct usb_composite_dev *cdev = &gi->cdev;
\tstruct usb_configuration *c;
\tstruct usb_string *s;
\tunsigned i;
\tint ret;

\tlist_for_each_entry(c, &gi->cdev.configs, list) {
\t\tstruct config_usb_cfg *cfg;
\t\tstruct usb_function *f;
\t\tstruct usb_function *tmp;

\t\tcfg = container_of(c, struct config_usb_cfg, c);

\t\tlist_for_each_entry_safe(f, tmp, &cfg->func_list, list) {
\t\t\tlist_del(&f->list);
\t\t\tret = usb_add_function(c, f);
\t\t\tif (ret) {
\t\t\t\tlist_add(&f->list, &cfg->func_list);
\t\t\t\tgoto err_purge_funcs;
\t\t\t}
\t\t}
\t\tusb_ep_autoconfig_reset(cdev->gadget);
\t}
\treturn 0;

err_purge_funcs:
\tpurge_configs_funcs(gi);
\treturn ret;
}
"""

DRIVERS_KCONFIG = """\
# SPDX-License-Identifier: GPL-2.0
menu "Device Drivers"

source "drivers/usb/Kconfig"

endmenu
"""

DRIVERS_MAKEFILE = """\
# SPDX-License-Identifier: GPL-2.0
obj-y\t\t\t\t+= usb/
"""

KSU_RULES = """\
#include "selinux.h"

void apply_kernelsu_rules()
{
\tstruct policydb *db;

\tksu_allow(db, "init", "adb_data_file", "file", ALL);
\tksu_allow(db, "init", "adb_data_file", "dir", ALL);
}
"""


class SyntheticTree:
    """A minimal kernel tree carrying only the anchors install.py owns."""

    def __init__(
        self,
        base: Path,
        version: str = "5.15",
        *,
        with_ksu: bool = False,
        with_ecc_header: bool = True,
        configfs: str = CONFIGFS,
    ) -> None:
        self.base = base
        self.kernel_root = base / "kernel-root"
        self.common = self.kernel_root / "common"
        self.defconfig = self.kernel_root / "gki_defconfig"
        self.version = version

        major, minor = version.split(".")
        self.write(
            self.common / "Makefile",
            f"# SPDX-License-Identifier: GPL-2.0\nVERSION = {major}\n"
            f"PATCHLEVEL = {minor}\nSUBLEVEL = 178\nEXTRAVERSION =\n",
        )
        self.write(self.common / "drivers/Kconfig", DRIVERS_KCONFIG)
        self.write(self.common / "drivers/Makefile", DRIVERS_MAKEFILE)
        self.write(self.common / "drivers/usb/gadget/configfs.c", configfs)
        if with_ecc_header:
            self.write(self.common / self.ecc_header, "/* stub ECC header */\n")
        if with_ksu:
            self.write(self.common / "drivers/kernelsu/selinux/rules.c", KSU_RULES)
        self.write(self.defconfig, "CONFIG_USB_GADGET=y\nCONFIG_CRYPTO_ECC=m\n")

    @property
    def ecc_header(self) -> str:
        return "crypto/ecc.h" if self.version == "5.15" else "include/crypto/internal/ecc.h"

    @property
    def ksu_rules(self) -> Path:
        return self.common / "drivers/kernelsu/selinux/rules.c"

    @property
    def configfs(self) -> Path:
        return self.common / "drivers/usb/gadget/configfs.c"

    @staticmethod
    def write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def read(self, relative: str) -> str:
        return (self.common / relative).read_text(encoding="utf-8")

    def run(self, command: str, *, defconfig: bool = True) -> subprocess.CompletedProcess[str]:
        argv = [
            sys.executable,
            str(INSTALLER),
            command,
            "--kernel-root",
            str(self.kernel_root),
            "--module-root",
            str(REPOSITORY),
        ]
        if defconfig:
            argv += ["--defconfig", str(self.defconfig)]
        return subprocess.run(argv, capture_output=True, text=True, check=False)

    def install(self, **kwargs: bool) -> subprocess.CompletedProcess[str]:
        return self.run("install", **kwargs)

    def verify(self, **kwargs: bool) -> subprocess.CompletedProcess[str]:
        return self.run("verify", **kwargs)

    def full_install(self) -> None:
        assert self.install().returncode == 0
        assert self.run("enable-config").returncode == 0


class InstallerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="abk-fido-test-")
        self.addCleanup(self._temporary.cleanup)
        self.base = Path(self._temporary.name)

    def tree(self, **kwargs: object) -> SyntheticTree:
        return SyntheticTree(self.base, **kwargs)  # type: ignore[arg-type]

    def assertFailed(self, result: subprocess.CompletedProcess[str], fragment: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(fragment, result.stdout + result.stderr)


class DetectTest(InstallerTestCase):
    def test_detects_both_supported_kernel_lines(self) -> None:
        for version, header in (("5.15", "crypto/ecc.h"), ("6.1", "include/crypto/internal/ecc.h")):
            with self.subTest(version=version):
                # Each line needs its own base: the two ECC header layouts are
                # mutually exclusive and the installer rejects a tree with both.
                tree = SyntheticTree(self.base / f"detect-{version}", version=version)
                result = tree.run("detect", defconfig=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"kernel={version}", result.stdout)
                self.assertIn(f"ecc_header={header}", result.stdout)

    def test_rejects_unsupported_kernel_line(self) -> None:
        tree = self.tree()
        SyntheticTree.write(
            tree.common / "Makefile", "VERSION = 6\nPATCHLEVEL = 6\nSUBLEVEL = 100\n"
        )
        self.assertFailed(tree.run("detect", defconfig=False), "unsupported kernel line 6.6")

    def test_rejects_tree_without_kernel_makefile(self) -> None:
        tree = self.tree()
        (tree.common / "Makefile").unlink()
        self.assertFailed(tree.run("detect", defconfig=False), "kernel Makefile not found")

    def test_rejects_missing_ecc_header(self) -> None:
        tree = self.tree(with_ecc_header=False)
        self.assertFailed(tree.run("detect", defconfig=False), "missing the internal ECC header")

    def test_rejects_kernel_line_header_mismatch(self) -> None:
        tree = self.tree(version="5.15")
        SyntheticTree.write(tree.common / "include/crypto/internal/ecc.h", "/* wrong line */\n")
        self.assertFailed(
            tree.run("detect", defconfig=False), "does not match its reported kernel line"
        )

    def test_reports_kernelsu_presence(self) -> None:
        self.assertIn("ksu=absent", self.tree().run("detect", defconfig=False).stdout)
        tree = SyntheticTree(self.base / "with-ksu", with_ksu=True)
        self.assertIn("rules.c", tree.run("detect", defconfig=False).stdout)


class InstallTest(InstallerTestCase):
    def test_installs_sources_wiring_and_hooks(self) -> None:
        tree = self.tree()
        result = tree.install()
        self.assertEqual(result.returncode, 0, result.stderr)

        for name in ("Kconfig", "Makefile", "core.c"):
            installed = tree.common / "drivers/abk_fido_key" / name
            expected = REPOSITORY / "files/drivers/abk_fido_key" / name
            self.assertEqual(
                installed.read_text(encoding="utf-8"), expected.read_text(encoding="utf-8")
            )
        self.assertEqual(
            (tree.common / "include/linux/abk_fido_key.h").read_text(encoding="utf-8"),
            (REPOSITORY / "files/include/linux/abk_fido_key.h").read_text(encoding="utf-8"),
        )

        self.assertIn('source "drivers/abk_fido_key/Kconfig"', tree.read("drivers/Kconfig"))
        self.assertIn(
            "obj-$(CONFIG_ABK_FIDO_KEY) += abk_fido_key/", tree.read("drivers/Makefile")
        )

        configfs = tree.read("drivers/usb/gadget/configfs.c")
        self.assertIn("#include <linux/abk_fido_key.h>", configfs)
        self.assertIn("abk_fido_key_prepare_config(cdev, c, &cfg->func_list)", configfs)
        self.assertIn("abk_fido_key_release_config(&cfg->func_list)", configfs)
        self.assertEqual(configfs.count(MARKER), 2)

    def test_prepare_hook_precedes_the_function_list_loop(self) -> None:
        tree = self.tree()
        self.assertEqual(tree.install().returncode, 0)
        configfs = tree.read("drivers/usb/gadget/configfs.c")
        self.assertLess(
            configfs.index("abk_fido_key_prepare_config"),
            configfs.index("list_for_each_entry_safe(f, tmp, &cfg->func_list, list)"),
        )

    def test_include_precedes_both_hooks(self) -> None:
        tree = self.tree()
        self.assertEqual(tree.install().returncode, 0)
        configfs = tree.read("drivers/usb/gadget/configfs.c")
        include_at = configfs.index("#include <linux/abk_fido_key.h>")
        self.assertLess(include_at, configfs.index("abk_fido_key_release_config"))
        self.assertLess(include_at, configfs.index("abk_fido_key_prepare_config"))

    def test_install_is_idempotent(self) -> None:
        tree = self.tree(with_ksu=True)
        self.assertEqual(tree.install().returncode, 0)
        snapshot = {
            path: path.read_bytes()
            for path in tree.common.rglob("*")
            if path.is_file()
        }
        second = tree.install()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotIn("updated", second.stdout)
        for path, content in snapshot.items():
            self.assertEqual(path.read_bytes(), content, path)

    def test_installs_on_both_kernel_lines(self) -> None:
        for version in ("5.15", "6.1"):
            with self.subTest(version=version):
                tree = SyntheticTree(self.base / f"line-{version}", version=version)
                tree.full_install()
                verified = tree.verify()
                self.assertEqual(verified.returncode, 0, verified.stderr)
                self.assertIn(f"kernel={version}", verified.stdout)


class AnchorTest(InstallerTestCase):
    def test_rejects_missing_include_anchor(self) -> None:
        tree = self.tree(configfs=CONFIGFS.replace('#include "u_os_desc.h"\n', ""))
        self.assertFailed(tree.install(), "configfs include anchor not found")

    def test_rejects_missing_bind_anchor(self) -> None:
        broken = CONFIGFS.replace(
            "\t\tlist_for_each_entry_safe(f, tmp, &cfg->func_list, list) {",
            "\t\tlist_for_each_entry(f, &cfg->func_list, list) {",
        )
        self.assertFailed(self.tree(configfs=broken).install(), "gadget bind anchor not found")

    def test_rejects_missing_release_anchor(self) -> None:
        broken = CONFIGFS.replace(
            "\tstruct config_usb_cfg *cfg = to_config_usb_cfg(item);",
            "\tstruct config_usb_cfg *cfg = container_of(item, struct config_usb_cfg, c.item);",
        )
        self.assertFailed(self.tree(configfs=broken).install(), "config release anchor not found")

    def test_tolerates_a_missing_blank_line_after_the_release_declaration(self) -> None:
        # The anchor stops at the declaration rather than requiring the blank
        # line that follows it upstream, so tighter formatting still matches.
        tight = CONFIGFS.replace(
            "\tstruct config_usb_cfg *cfg = to_config_usb_cfg(item);\n\n"
            "\tWARN_ON(!list_empty(&cfg->c.functions));",
            "\tstruct config_usb_cfg *cfg = to_config_usb_cfg(item);\n"
            "\tWARN_ON(!list_empty(&cfg->c.functions));",
        )
        tree = self.tree(configfs=tight)
        result = tree.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "abk_fido_key_release_config(&cfg->func_list)",
            tree.read("drivers/usb/gadget/configfs.c"),
        )

    def test_rejects_ambiguous_bind_anchor(self) -> None:
        loop = "\t\tlist_for_each_entry_safe(f, tmp, &cfg->func_list, list) {"
        duplicated = CONFIGFS.replace(loop, loop + "\n\t\t}\n" + loop, 1)
        self.assertFailed(self.tree(configfs=duplicated).install(), "is ambiguous")

    def test_ignores_anchor_text_inside_a_comment(self) -> None:
        commented = CONFIGFS.replace(
            "static void gadget_config_attr_release",
            "/* list_for_each_entry_safe(f, tmp, &cfg->func_list, list) { */\n"
            "static void gadget_config_attr_release",
            1,
        )
        tree = self.tree(configfs=commented)
        result = tree.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(tree.read("drivers/usb/gadget/configfs.c").count(MARKER), 2)

    def test_rejects_bind_scope_without_required_identifiers(self) -> None:
        broken = CONFIGFS.replace("\tstruct usb_composite_dev *cdev = &gi->cdev;\n", "")
        self.assertFailed(self.tree(configfs=broken).install(), "does not provide 'cdev'")

    def test_rejects_unmarked_preexisting_injection(self) -> None:
        tampered = CONFIGFS.replace(
            '#include "u_os_desc.h"',
            '#include "u_os_desc.h"\n#include <linux/abk_fido_key.h>',
            1,
        )
        self.assertFailed(self.tree(configfs=tampered).install(), "conflicting or partial")

    def test_rejects_partial_injection(self) -> None:
        tree = self.tree()
        self.assertEqual(tree.install().returncode, 0)
        path = tree.configfs
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "\tabk_fido_key_release_config(&cfg->func_list);\n", ""
            ),
            encoding="utf-8",
        )
        self.assertFailed(tree.install(), "incomplete FIDO injection")


class SepolicyTest(InstallerTestCase):
    def test_injects_metadata_rules_when_kernelsu_is_present(self) -> None:
        tree = self.tree(with_ksu=True)
        self.assertEqual(tree.install().returncode, 0)
        rules = tree.ksu_rules.read_text(encoding="utf-8")
        self.assertIn(f"{MARKER}: metadata store access", rules)
        for target in ("dir", "file"):
            self.assertIn(f'ksu_allow(db, "kernel", "metadata_file", "{target}"', rules)
        # The block must land inside apply_kernelsu_rules(), after the last
        # existing ksu_allow() call, not after the closing brace.
        self.assertLess(rules.index(MARKER), rules.rindex("}"))

    def test_skips_and_warns_without_kernelsu(self) -> None:
        tree = self.tree(with_ksu=False)
        result = tree.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no KernelSU rules.c found", result.stdout + result.stderr)

    def test_sepolicy_injection_is_idempotent(self) -> None:
        tree = self.tree(with_ksu=True)
        self.assertEqual(tree.install().returncode, 0)
        first = tree.ksu_rules.read_text(encoding="utf-8")
        self.assertEqual(tree.install().returncode, 0)
        self.assertEqual(tree.ksu_rules.read_text(encoding="utf-8"), first)

    def test_rejects_unmarked_metadata_rules(self) -> None:
        tampered = KSU_RULES.replace(
            '\tksu_allow(db, "init", "adb_data_file", "dir", ALL);',
            '\tksu_allow(db, "init", "adb_data_file", "dir", ALL);\n'
            '\tksu_allow(db, "kernel", "metadata_file", "dir", "search");',
        )
        tree = self.tree(with_ksu=True)
        tree.ksu_rules.write_text(tampered, encoding="utf-8")
        self.assertFailed(tree.install(), "unmarked ABK FIDO sepolicy injection")

    def test_rejects_rules_without_any_anchor(self) -> None:
        tree = self.tree(with_ksu=True)
        tree.ksu_rules.write_text("void apply_kernelsu_rules() {}\n", encoding="utf-8")
        self.assertFailed(tree.install(), "no ksu_allow() anchor found")


class RollbackTest(InstallerTestCase):
    def test_restores_every_touched_file_when_a_later_step_fails(self) -> None:
        # Sources and build wiring are installed before configfs is patched, so a
        # bad configfs anchor must roll all of it back.
        tree = self.tree(configfs="int no_anchors_here;\n")
        kconfig_before = tree.read("drivers/Kconfig")
        makefile_before = tree.read("drivers/Makefile")

        result = tree.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rolled back", result.stderr)

        self.assertEqual(tree.read("drivers/Kconfig"), kconfig_before)
        self.assertEqual(tree.read("drivers/Makefile"), makefile_before)
        self.assertFalse((tree.common / "drivers/abk_fido_key").exists())
        self.assertFalse((tree.common / "include/linux/abk_fido_key.h").exists())

    def test_rollback_leaves_sepolicy_untouched(self) -> None:
        tree = self.tree(with_ksu=True, configfs="int no_anchors_here;\n")
        before = tree.ksu_rules.read_text(encoding="utf-8")
        self.assertNotEqual(tree.install().returncode, 0)
        self.assertEqual(tree.ksu_rules.read_text(encoding="utf-8"), before)

class VerifyTest(InstallerTestCase):
    def test_verify_fails_before_install(self) -> None:
        self.assertFailed(self.tree().verify(), "validation would update")

    def test_verify_requires_enabled_defconfig(self) -> None:
        tree = self.tree()
        self.assertEqual(tree.install().returncode, 0)
        self.assertFailed(tree.verify(), "CONFIG_ABK_FIDO_KEY=y is missing")

    def test_verify_passes_after_full_install(self) -> None:
        tree = self.tree(with_ksu=True)
        tree.full_install()
        result = tree.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified kernel=5.15", result.stdout)
        self.assertIn("ecc_header=crypto/ecc.h", result.stdout)

    def test_verify_detects_tampered_driver_source(self) -> None:
        tree = self.tree()
        tree.full_install()
        target = tree.common / "drivers/abk_fido_key/core.c"
        target.write_text(
            target.read_text(encoding="utf-8") + "/* tampered */\n", encoding="utf-8"
        )
        self.assertFailed(tree.verify(), "validation would update")

    def test_verify_detects_removed_build_wiring(self) -> None:
        tree = self.tree()
        tree.full_install()
        path = tree.common / "drivers/Makefile"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "obj-$(CONFIG_ABK_FIDO_KEY) += abk_fido_key/\n", ""
            ),
            encoding="utf-8",
        )
        self.assertFailed(tree.verify(), "validation would update")

    def test_verify_detects_removed_sepolicy_rules(self) -> None:
        tree = self.tree(with_ksu=True)
        tree.full_install()
        tree.ksu_rules.write_text(KSU_RULES, encoding="utf-8")
        self.assertFailed(tree.verify(), "validation would update")

    def test_verify_rejects_module_built_as_loadable(self) -> None:
        tree = self.tree()
        tree.full_install()
        tree.defconfig.write_text(
            tree.defconfig.read_text(encoding="utf-8").replace(
                "CONFIG_ABK_FIDO_KEY=y", "CONFIG_ABK_FIDO_KEY=m"
            ),
            encoding="utf-8",
        )
        self.assertFailed(tree.verify(), "is unsupported; the FIDO driver is built in")

    def test_install_requires_usb_gadget(self) -> None:
        tree = self.tree()
        tree.defconfig.write_text("CONFIG_CRYPTO_ECC=y\n", encoding="utf-8")
        self.assertFailed(tree.install(), "CONFIG_USB_GADGET=y is required")


class DriverTemplateTest(unittest.TestCase):
    """Guard the shipped core.c against the shapes verify() rejects.

    verify() compares the installed file byte-for-byte with this template, so a
    template that fails its own needle checks would break every build after the
    tree is installed rather than here.
    """

    def setUp(self) -> None:
        self.core = (REPOSITORY / "files/drivers/abk_fido_key/core.c").read_text(
            encoding="utf-8"
        )
        self.installer = _load_installer()

    def test_template_satisfies_every_required_needle(self) -> None:
        for needle in self.installer.CORE_NEEDLES:
            with self.subTest(needle=needle):
                self.assertIn(needle, self.core)

    def test_template_avoids_every_forbidden_needle(self) -> None:
        for needle in self.installer.CORE_FORBIDDEN_NEEDLES:
            with self.subTest(needle=needle):
                self.assertNotIn(needle, self.core)

    def test_gadget_function_is_registered_exactly_once(self) -> None:
        # DECLARE_USB_FUNCTION only defines the driver struct, so the single
        # module_init in the driver must register and unregister it itself.
        self.assertEqual(self.core.count("usb_function_register(&abk_fidousb_func)"), 1)
        self.assertEqual(self.core.count("usb_function_unregister(&abk_fidousb_func)"), 1)
        self.assertEqual(self.core.count("module_init("), 1)
        self.assertEqual(self.core.count("module_exit("), 1)


class DefconfigTest(InstallerTestCase):
    def test_enable_config_promotes_tristate_crypto_to_builtin(self) -> None:
        tree = self.tree()
        self.assertIn("CONFIG_CRYPTO_ECC=m", tree.defconfig.read_text(encoding="utf-8"))
        self.assertEqual(tree.install().returncode, 0)
        self.assertEqual(tree.run("enable-config").returncode, 0)
        config = tree.defconfig.read_text(encoding="utf-8")
        self.assertIn("CONFIG_CRYPTO_ECC=y", config)
        self.assertNotIn("CONFIG_CRYPTO_ECC=m", config)
        self.assertIn("CONFIG_CRYPTO_ECDH=y", config)

    def test_enable_config_replaces_a_negated_symbol(self) -> None:
        tree = self.tree()
        tree.defconfig.write_text(
            "CONFIG_USB_GADGET=y\n# CONFIG_ABK_FIDO_KEY is not set\n", encoding="utf-8"
        )
        self.assertEqual(tree.run("enable-config").returncode, 0)
        config = tree.defconfig.read_text(encoding="utf-8")
        self.assertIn("CONFIG_ABK_FIDO_KEY=y", config)
        self.assertNotIn("# CONFIG_ABK_FIDO_KEY is not set", config)

    def test_enable_config_is_idempotent(self) -> None:
        tree = self.tree()
        self.assertEqual(tree.run("enable-config").returncode, 0)
        first = tree.defconfig.read_text(encoding="utf-8")
        self.assertEqual(tree.run("enable-config").returncode, 0)
        self.assertEqual(tree.defconfig.read_text(encoding="utf-8"), first)

    def test_rejects_duplicate_config_entries(self) -> None:
        tree = self.tree()
        tree.defconfig.write_text(
            "CONFIG_USB_GADGET=y\nCONFIG_USB_GADGET=y\n", encoding="utf-8"
        )
        self.assertFailed(tree.install(), "duplicate CONFIG_USB_GADGET")

    def test_enable_config_requires_a_defconfig(self) -> None:
        self.assertFailed(
            self.tree().run("enable-config", defconfig=False), "requires --defconfig"
        )


def _clean_env() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key not in {"KERNEL_ROOT", "DEFCONFIG", "CUSTOM_EXTERNAL_MODULE_STAGE"}
    }


class SetupStageTest(InstallerTestCase):
    def _run_stage(self, tree: SyntheticTree, stage: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SETUP)],
            capture_output=True,
            text=True,
            check=False,
            env={
                **_clean_env(),
                "KERNEL_ROOT": str(tree.kernel_root),
                "DEFCONFIG": str(tree.defconfig),
                "CUSTOM_EXTERNAL_MODULE_STAGE": stage,
            },
        )

    def test_both_stages_install_and_verify(self) -> None:
        tree = self.tree(with_ksu=True)
        after_patch = self._run_stage(tree, "after_patch")
        self.assertEqual(after_patch.returncode, 0, after_patch.stderr)
        self.assertIn("kernel version: 5.15.178", after_patch.stdout)

        before_build = self._run_stage(tree, "before_build")
        self.assertEqual(before_build.returncode, 0, before_build.stderr)
        self.assertIn("verified kernel=5.15", before_build.stdout)
        self.assertIn("CONFIG_ABK_FIDO_KEY=y", tree.defconfig.read_text(encoding="utf-8"))

    def test_before_build_alone_is_sufficient(self) -> None:
        # ABK users may select only one stage; before_build installs as well so a
        # single-stage configuration still produces a complete tree.
        tree = self.tree()
        result = self._run_stage(tree, "before_build")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified kernel=5.15", result.stdout)

    def test_rejects_unknown_stage(self) -> None:
        result = self._run_stage(self.tree(), "during_build")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported CUSTOM_EXTERNAL_MODULE_STAGE", result.stderr)

    def test_requires_environment(self) -> None:
        result = subprocess.run(
            ["bash", str(SETUP)],
            capture_output=True,
            text=True,
            check=False,
            env={**_clean_env(), "CUSTOM_EXTERNAL_MODULE_STAGE": "after_patch"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required environment variable is empty", result.stderr)


if __name__ == "__main__":
    unittest.main()

