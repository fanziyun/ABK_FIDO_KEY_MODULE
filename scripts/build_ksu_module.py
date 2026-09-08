#!/usr/bin/env python3
"""Pack the KernelSU SELinux module into a flashable zip.

The module source lives in `ksu/abk_fido_selinux/`; this script turns it into
`build/ksu/abk_fido_selinux.zip`, which the KernelSU manager can flash and
`ksud module install` can install over adb.

Two details matter:

* The zip entries sit at the zip root, because KernelSU extracts them straight
  into `/data/adb/modules/<id>`. No `META-INF/` is shipped: `ksud module
  install` has its own unpacker (it even skips `META-INF/*`).
* The zip file name becomes the module directory name, so it must equal the
  `id=` in module.prop. `--output` may rename it, but then the module is
  installed under that name.

Run: python3 scripts/build_ksu_module.py
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
MODULE_SOURCE = REPOSITORY / "ksu/abk_fido_selinux"
DEFAULT_OUTPUT = REPOSITORY / "build/ksu/abk_fido_selinux.zip"

EXECUTABLE_MODE = 0o755
REGULAR_MODE = 0o644


def read_module_id(source: Path) -> str:
    """The `id=` of module.prop, which must also be the module directory name."""
    for line in (source / "module.prop").read_text(encoding="utf-8").splitlines():
        if line.startswith("id="):
            return line[3:].strip()
    raise SystemExit(f"no id= in {source / 'module.prop'}")


def module_files(source: Path) -> list[Path]:
    files = sorted(p for p in source.rglob("*") if p.is_file())
    if not files:
        raise SystemExit(f"no module files in {source}")
    return files


def build(source: Path = MODULE_SOURCE, output: Path = DEFAULT_OUTPUT) -> Path:
    module_id = read_module_id(source)
    output.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in module_files(source):
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            mode = EXECUTABLE_MODE if relative.endswith(".sh") else REGULAR_MODE
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())

    if output.stem != module_id:
        print(
            f"warning: {output.name} does not match id={module_id}; "
            f"KernelSU names the module directory after the zip",
            file=sys.stderr,
        )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, default=MODULE_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    output = build(args.source, args.output)
    print(f"{output} ({output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
