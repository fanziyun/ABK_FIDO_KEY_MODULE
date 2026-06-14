#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


HELPER_NEEDLE = """static int inode_doinit_with_dentry(struct inode *inode, struct dentry *opt_dentry);\n"""
HELPER_BLOCK = """static bool selinux_abk_fido_persist_path_allowed(const char *path)\n{\n\tstatic const char * const allowed_paths[] = {\n\t\t\"/metadata\",\n\t\t\"/metadata/abk_fido_store.bin\",\n\t\t\"/metadata/abk_fido.db\",\n\t\t\"/data/adb\",\n\t\t\"/data/adb/abk_fido_store.bin\",\n\t\t\"/data/adb/abk_fido.db\",\n\t\t\"/mnt/vendor/persist\",\n\t\t\"/mnt/vendor/persist/abk_fido_store.bin\",\n\t\t\"/mnt/vendor/persist/abk_fido.db\",\n\t\t\"/data/local/tmp\",\n\t\t\"/data/local/tmp/abk_fido_store.bin\",\n\t\t\"/data/local/tmp/abk_fido.db\",\n\t\tNULL,\n\t};\n\tint i;\n\n\tif (!path || IS_ERR(path))\n\t\treturn false;\n\n\tfor (i = 0; allowed_paths[i]; i++) {\n\t\tif (!strcmp(path, allowed_paths[i]))\n\t\t\treturn true;\n\t}\n\n\treturn false;\n}\n\nstatic bool selinux_abk_fido_persist_dentry_allowed(const struct dentry *dentry,\n\t\t\t\t\t\t    char *path_out,\n\t\t\t\t\t\t    size_t path_out_len)\n{\n\tchar *buffer, *path;\n\tbool allowed = false;\n\n\tif (!dentry)\n\t\treturn false;\n\n\tbuffer = (char *)__get_free_page(GFP_ATOMIC);\n\tif (!buffer)\n\t\treturn false;\n\n\tpath = dentry_path_raw(dentry, buffer, PAGE_SIZE);\n\tif (!IS_ERR(path) && selinux_abk_fido_persist_path_allowed(path)) {\n\t\tallowed = true;\n\t\tif (path_out && path_out_len)\n\t\t\tstrscpy(path_out, path, path_out_len);\n\t}\n\n\tfree_page((unsigned long)buffer);\n\treturn allowed;\n}\n\nstatic bool selinux_abk_fido_persist_inode_allowed(struct inode *inode,\n\t\t\t\t\t\t   char *path_out,\n\t\t\t\t\t\t   size_t path_out_len)\n{\n\tstruct dentry *dentry;\n\tbool allowed;\n\n\tif (!inode)\n\t\treturn false;\n\n\tdentry = d_find_alias(inode);\n\tif (!dentry)\n\t\tdentry = d_find_any_alias(inode);\n\tif (!dentry)\n\t\treturn false;\n\n\tallowed = selinux_abk_fido_persist_dentry_allowed(dentry,\n\t\t\t\t\t\t path_out,\n\t\t\t\t\t\t path_out_len);\n\tdput(dentry);\n\treturn allowed;\n}\n\nstatic bool selinux_abk_fido_kernel_bypass(const struct cred *cred,\n\t\t\t\t\t   struct inode *inode,\n\t\t\t\t\t   const struct common_audit_data *adp,\n\t\t\t\t\t   const char *op)\n{\n\tchar path[160] = \"\";\n\tbool allowed = false;\n\n\tif (!cred || cred_sid(cred) != SECINITSID_KERNEL)\n\t\treturn false;\n\n\tif (adp) {\n\t\tswitch (adp->type) {\n\t\tcase LSM_AUDIT_DATA_DENTRY:\n\t\t\tallowed = selinux_abk_fido_persist_dentry_allowed(\n\t\t\t\tadp->u.dentry, path, sizeof(path));\n\t\t\tbreak;\n\t\tcase LSM_AUDIT_DATA_PATH:\n\t\t\tallowed = selinux_abk_fido_persist_dentry_allowed(\n\t\t\t\tadp->u.path.dentry, path, sizeof(path));\n\t\t\tbreak;\n\t\tcase LSM_AUDIT_DATA_FILE:\n\t\t\tallowed = selinux_abk_fido_persist_dentry_allowed(\n\t\t\t\tfile_dentry(adp->u.file), path, sizeof(path));\n\t\t\tbreak;\n\t\tdefault:\n\t\t\tbreak;\n\t\t}\n\t}\n\n\tif (!allowed)\n\t\tallowed = selinux_abk_fido_persist_inode_allowed(inode, path,\n\t\t\t\t\t\t\t sizeof(path));\n\n\tif (allowed)\n\t\tpr_info_ratelimited(\"SELinux: ABK FIDO bypass sid=kernel op=%s path=%s\\n\",\n\t\t\t\t    op, path[0] ? path : \"?\");\n\n\treturn allowed;\n}\n\nstatic int inode_doinit_with_dentry(struct inode *inode, struct dentry *opt_dentry);\n"""

INODE_HAS_PERM_NEEDLE = """\tif (unlikely(IS_PRIVATE(inode)))\n\t\treturn 0;\n\n\tsid = cred_sid(cred);\n"""
INODE_HAS_PERM_BLOCK = """\tif (unlikely(IS_PRIVATE(inode)))\n\t\treturn 0;\n\n\tif (selinux_abk_fido_kernel_bypass(cred, inode, adp, \"inode_has_perm\"))\n\t\treturn 0;\n\n\tsid = cred_sid(cred);\n"""

MAY_CREATE_NEEDLE = """\tsid = tsec->sid;\n\n\tad.type = LSM_AUDIT_DATA_DENTRY;\n"""
MAY_CREATE_BLOCK = """\tsid = tsec->sid;\n\n\tif (sid == SECINITSID_KERNEL &&\n\t    selinux_abk_fido_persist_dentry_allowed(dentry, NULL, 0)) {\n\t\tpr_info_ratelimited(\"SELinux: ABK FIDO bypass sid=kernel op=may_create\\n\");\n\t\treturn 0;\n\t}\n\n\tad.type = LSM_AUDIT_DATA_DENTRY;\n"""

INODE_PERMISSION_NEEDLE = """\tif (unlikely(IS_PRIVATE(inode)))\n\t\treturn 0;\n\n\tperms = file_mask_to_av(inode->i_mode, mask);\n"""
INODE_PERMISSION_BLOCK = """\tif (unlikely(IS_PRIVATE(inode)))\n\t\treturn 0;\n\n\tif (selinux_abk_fido_kernel_bypass(cred, inode, NULL,\n\t\t\t\t\t  \"inode_permission\"))\n\t\treturn 0;\n\n\tperms = file_mask_to_av(inode->i_mode, mask);\n"""

INODE_SETATTR_NEEDLE = """\tif (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID |\n\t\t\tATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_TIMES_SET))\n"""
INODE_SETATTR_BLOCK = """\tif (selinux_abk_fido_persist_dentry_allowed(dentry, NULL, 0) &&\n\t    cred_sid(cred) == SECINITSID_KERNEL) {\n\t\tpr_info_ratelimited(\"SELinux: ABK FIDO bypass sid=kernel op=inode_setattr\\n\");\n\t\treturn 0;\n\t}\n\n\tif (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID |\n\t\t\tATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_TIMES_SET))\n"""

FILE_PATH_HAS_PERM_NEEDLE = """\tad.type = LSM_AUDIT_DATA_FILE;\n\tad.u.file = file;\n\treturn inode_has_perm(cred, file_inode(file), av, &ad);\n"""
FILE_PATH_HAS_PERM_BLOCK = """\tad.type = LSM_AUDIT_DATA_FILE;\n\tad.u.file = file;\n\tif (selinux_abk_fido_kernel_bypass(cred, file_inode(file), &ad,\n\t\t\t\t\t  \"file_path_has_perm\"))\n\t\treturn 0;\n\treturn inode_has_perm(cred, file_inode(file), av, &ad);\n"""

FILE_PERMISSION_NEEDLE = """\tif (!mask)\n\t\t/* No permission to check.  Existence test. */\n\t\treturn 0;\n\n\tisec = inode_security(inode);\n"""
FILE_PERMISSION_BLOCK = """\tif (!mask)\n\t\t/* No permission to check.  Existence test. */\n\t\treturn 0;\n\n\tif (selinux_abk_fido_kernel_bypass(current_cred(), inode, NULL,\n\t\t\t\t\t  \"file_permission\"))\n\t\treturn 0;\n\n\tisec = inode_security(inode);\n"""


def inject_once(text: str, needle: str, block: str, marker: str, path: Path) -> str:
    if marker in text:
        return text
    if needle not in text:
        raise SystemExit(f"injection point not found in {path}: {marker}")
    return text.replace(needle, block, 1)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: patch_selinux_for_abk_fido.py <hooks.c>", file=sys.stderr)
        return 1

    path = Path(sys.argv[1])
    text = path.read_text()
    updated = text

    updated = inject_once(updated, HELPER_NEEDLE, HELPER_BLOCK, "selinux_abk_fido_kernel_bypass", path)
    updated = inject_once(updated, INODE_HAS_PERM_NEEDLE, INODE_HAS_PERM_BLOCK, "inode_has_perm\"", path)
    updated = inject_once(updated, MAY_CREATE_NEEDLE, MAY_CREATE_BLOCK, "op=may_create", path)
    updated = inject_once(updated, INODE_PERMISSION_NEEDLE, INODE_PERMISSION_BLOCK, "inode_permission\"", path)
    updated = inject_once(updated, INODE_SETATTR_NEEDLE, INODE_SETATTR_BLOCK, "op=inode_setattr", path)
    updated = inject_once(updated, FILE_PATH_HAS_PERM_NEEDLE, FILE_PATH_HAS_PERM_BLOCK, "file_path_has_perm", path)
    updated = inject_once(updated, FILE_PERMISSION_NEEDLE, FILE_PERMISSION_BLOCK, "file_permission", path)

    if updated != text:
        path.write_text(updated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
