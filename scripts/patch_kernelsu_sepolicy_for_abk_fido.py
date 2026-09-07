#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


# KernelSU removed its init/adb_data_file rules in PR #3031
# (https://github.com/tiann/KernelSU/pull/3031), so that block no longer exists
# in any current rules.c and cannot serve as an injection needle. Anchor
# instead on the stable "our ksud triggered by init" rule that every KernelSU
# rules.c still carries.
NEEDLE = """    // our ksud triggered by init
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, ALL, ALL);

"""
BLOCK = """    // our ksud triggered by init
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, ALL, ALL);

    /* ABK FIDO: allow kernel domain access to the persisted metadata store.
     * create is needed for the first O_CREAT of the blob (write alone only
     * covers an already existing file).
     */
    ksu_allow(db, "kernel", "metadata_file", "dir", "search");
    ksu_allow(db, "kernel", "metadata_file", "file", "create");
    ksu_allow(db, "kernel", "metadata_file", "file", "open");
    ksu_allow(db, "kernel", "metadata_file", "file", "read");
    ksu_allow(db, "kernel", "metadata_file", "file", "write");
    ksu_allow(db, "kernel", "metadata_file", "file", "getattr");

    /* ABK FIDO: allow a userspace root shell (the ksud/su domain the companion
     * app drives through libsu) to write store edits back to the driver's sysfs
     * nodes (restore_metadata, store_blob) and to /metadata. Without these the
     * app is read-only and rename/delete/import fail with "Permission denied".
     * The exact root domain varies: KernelSU's su runs as "magisk", and ADB or
     * a plain userdebug su is "su", so both are granted (repeats are harmless).
     */
    ksu_allow(db, KERNEL_SU_DOMAIN, "sysfs", "dir", "search");
    ksu_allow(db, KERNEL_SU_DOMAIN, "sysfs", "file", "open");
    ksu_allow(db, KERNEL_SU_DOMAIN, "sysfs", "file", "read");
    ksu_allow(db, KERNEL_SU_DOMAIN, "sysfs", "file", "write");
    ksu_allow(db, KERNEL_SU_DOMAIN, "sysfs", "file", "getattr");
    ksu_allow(db, KERNEL_SU_DOMAIN, "metadata_file", "file", "open");
    ksu_allow(db, KERNEL_SU_DOMAIN, "metadata_file", "file", "write");
    ksu_allow(db, "su", "sysfs", "dir", "search");
    ksu_allow(db, "su", "sysfs", "file", "open");
    ksu_allow(db, "su", "sysfs", "file", "write");
    ksu_allow(db, "su", "sysfs", "file", "getattr");
    ksu_allow(db, "su", "metadata_file", "file", "open");
    ksu_allow(db, "su", "metadata_file", "file", "write");
    ksu_allow(db, "magisk", "sysfs", "dir", "search");
    ksu_allow(db, "magisk", "sysfs", "file", "open");
    ksu_allow(db, "magisk", "sysfs", "file", "write");
    ksu_allow(db, "magisk", "sysfs", "file", "getattr");
    ksu_allow(db, "magisk", "metadata_file", "file", "open");
    ksu_allow(db, "magisk", "metadata_file", "file", "write");

"""
MARKER = "ABK FIDO: allow kernel domain access to the persisted metadata store."


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: patch_kernelsu_sepolicy_for_abk_fido.py <rules.c>", file=sys.stderr)
        return 1

    path = Path(sys.argv[1])
    text = path.read_text()
    if MARKER in text:
        return 0
    if NEEDLE not in text:
        raise SystemExit(f"injection point not found in {path}")

    path.write_text(text.replace(NEEDLE, BLOCK, 1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
