#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


NEEDLE = """    // restored from https://github.com/tiann/KernelSU/pull/3031\n    ksu_allow(db, \"init\", \"adb_data_file\", \"file\", ALL);\n    ksu_allow(db, \"init\", \"adb_data_file\", \"dir\", ALL); // #1289\n\n"""
BLOCK = """    // restored from https://github.com/tiann/KernelSU/pull/3031\n    ksu_allow(db, \"init\", \"adb_data_file\", \"file\", ALL);\n    ksu_allow(db, \"init\", \"adb_data_file\", \"dir\", ALL); // #1289\n\n    /* ABK FIDO: allow kernel domain access to the persisted metadata store. */\n    ksu_allow(db, \"kernel\", \"metadata_file\", \"dir\", \"search\");\n    ksu_allow(db, \"kernel\", \"metadata_file\", \"file\", \"open\");\n    ksu_allow(db, \"kernel\", \"metadata_file\", \"file\", \"read\");\n    ksu_allow(db, \"kernel\", \"metadata_file\", \"file\", \"write\");\n    ksu_allow(db, \"kernel\", \"metadata_file\", \"file\", \"getattr\");\n\n"""
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
