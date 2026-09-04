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
