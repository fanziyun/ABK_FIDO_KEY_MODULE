#!/usr/bin/env python3
"""Guard the driver against warnings that are errors on the older kernel line.

Android 13 / 5.15 builds with `-Wdeclaration-after-statement` (see the ACK
Makefile), and ABK builds with `-Werror`, so a declaration placed after a
statement fails the kernel build. Android 14 / 6.1 dropped that flag, which is
why such code can sit in the tree unnoticed until a 5.15 build runs.

This is a syntactic check, not a compiler. It exists so a plain `python3` CI job
catches the mistake without a cross toolchain, and it targets the shape that
actually broke the build: a `(void)arg;` cast written above the declarations it
was meant to follow.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
DRIVER = REPOSITORY / "files/drivers/abk_fido_key/core.c"

_C_LEXEME = re.compile(
    r'"(?:\\.|[^"\\])*"' r"|'(?:\\.|[^'\\])*'" r"|//[^\n]*" r"|/\*.*?\*/",
    flags=re.DOTALL,
)

# A function definition's signature ends with `)` on some line, then `{` alone on
# the next. Signatures wrap across lines in this driver, so track a candidate that
# starts at column zero and accept the `)` on any continuation line. Struct, union
# and enum definitions are excluded so file-scope member lists are never mistaken
# for executable code.
_SIGNATURE_START = re.compile(r"^(?!struct\b|union\b|enum\b|typedef\b|\})\S")
_SIGNATURE_END = re.compile(r"\)\s*$")

_TYPE = (
    r"(?:const\s+|static\s+|volatile\s+|register\s+)*"
    r"(?:unsigned\s+|signed\s+)?"
    r"(?:struct\s+\w+|union\s+\w+|enum\s+\w+|"
    r"void|char|short|int|long|bool|size_t|ssize_t|loff_t|"
    r"u8|u16|u32|u64|s8|s16|s32|s64|"
    r"__be16|__be32|__be64|__le16|__le32|__le64|"
    r"__poll_t|gfp_t|spinlock_t|wait_queue_head_t|atomic_t|"
    r"unsigned|long\s+long)"
)
_DECLARATION = re.compile(rf"^{_TYPE}(?:\s*\*)*\s+\**\w+")
# Kernel macros that declare a local without looking like a typed declaration.
_MACRO_DECLARATION = re.compile(
    r"^(?:DECLARE_[A-Z_]+|DEFINE_[A-Z_]+|LIST_HEAD|SHASH_DESC_ON_STACK)\s*\("
)
_VOID_CAST = re.compile(r"^\(\s*void\s*\)\s*\w+\s*;$")
_LABEL = re.compile(r"^\w+\s*:$")
_KEYWORD_STATEMENT = re.compile(
    r"^(?:if|for|while|do|switch|return|goto|break|continue|else)\b"
)


def _mask_comments_and_literals(text: str) -> str:
    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group())

    return _C_LEXEME.sub(blank, text)


_BRACKETED = re.compile(r"\[[^\[\]]*\]")


def _blank_array_dimensions(head: str) -> str:
    """Blank `[...]` contents so an array bound is not read as a call.

    `u8 buf[1 + sizeof(other)];` is a declaration, but its dimension holds a
    parenthesis. Innermost brackets are collapsed repeatedly so nested bounds
    such as `[SIZE(a[0])]` are handled too.
    """
    while True:
        collapsed = _BRACKETED.sub(lambda match: " " * len(match.group()), head)
        if collapsed == head:
            return collapsed
        head = collapsed


def _is_declaration(line: str) -> bool:
    if _KEYWORD_STATEMENT.match(line):
        return False
    if _MACRO_DECLARATION.match(line):
        return True
    if not _DECLARATION.match(line):
        return False
    # `int foo(void);` is a prototype and `ret = f(x);` is a call, not a
    # declaration of a local. Require the statement to end in a declarator.
    head = _blank_array_dimensions(line.split("=", 1)[0])
    return "(" not in head


def find_declarations_after_statements(text: str) -> list[tuple[int, str]]:
    """Return (line number, source line) for each declaration after a statement.

    Only the top level of a function body is inspected. A nested block opens a
    new scope where declarations are legal again, so those are skipped.
    """
    masked = _mask_comments_and_literals(text)
    raw_lines = text.splitlines()
    masked_lines = masked.splitlines()

    findings: list[tuple[int, str]] = []
    depth = 0
    saw_statement = False
    in_function = False
    in_preprocessor = False
    in_signature = False
    pending_signature = False

    for index, line in enumerate(masked_lines):
        stripped = line.strip()

        if in_preprocessor or stripped.startswith("#"):
            in_preprocessor = stripped.endswith("\\")
            continue
        if not stripped:
            continue

        if not in_function:
            if depth == 0:
                if stripped == "{" and pending_signature:
                    in_function = True
                    depth = 1
                    saw_statement = False
                    pending_signature = False
                    continue
                if _SIGNATURE_START.match(line):
                    # A new candidate signature begins at column zero. It counts
                    # once its parameter list closes, which may be a later line.
                    in_signature = not _SIGNATURE_END.search(stripped)
                    pending_signature = not in_signature
                elif in_signature and _SIGNATURE_END.search(stripped):
                    in_signature = False
                    pending_signature = True
            # Track braces outside functions so struct bodies are skipped whole.
            depth += line.count("{") - line.count("}")
            depth = max(depth, 0)
            continue

        opens = line.count("{")
        closes = line.count("}")

        if depth == 1 and not stripped.startswith("}") and not _LABEL.match(stripped):
            if _is_declaration(stripped):
                if saw_statement:
                    findings.append((index + 1, raw_lines[index].rstrip()))
            elif _VOID_CAST.match(stripped) or opens == 0:
                saw_statement = True

        depth += opens - closes
        if depth <= 0:
            depth = 0
            in_function = False
            saw_statement = False

    return findings


class DeclarationAfterStatementTest(unittest.TestCase):
    def test_driver_has_no_declaration_after_statement(self) -> None:
        findings = find_declarations_after_statements(DRIVER.read_text(encoding="utf-8"))
        self.assertEqual(
            findings,
            [],
            "declaration after statement fails the 5.15 build "
            "(-Wdeclaration-after-statement -Werror):\n"
            + "\n".join(f"  {DRIVER.name}:{line}: {code}" for line, code in findings),
        )

    def test_detector_catches_the_regression_it_guards(self) -> None:
        broken = (
            "static ssize_t reload_store_store(struct kobject *kobj)\n"
            "{\n"
            "\t(void)kobj;\n"
            "\tint ret;\n"
            "\n"
            "\treturn ret;\n"
            "}\n"
        )
        self.assertEqual([line for line, _ in find_declarations_after_statements(broken)], [4])

    def test_detector_accepts_the_corrected_form(self) -> None:
        fixed = (
            "static ssize_t reload_store_store(struct kobject *kobj)\n"
            "{\n"
            "\tint ret;\n"
            "\n"
            "\t(void)kobj;\n"
            "\n"
            "\treturn ret;\n"
            "}\n"
        )
        self.assertEqual(find_declarations_after_statements(fixed), [])

    def test_detector_ignores_declarations_in_nested_scopes(self) -> None:
        nested = (
            "static int f(int a)\n"
            "{\n"
            "\tint ret = 0;\n"
            "\n"
            "\tif (a) {\n"
            "\t\tint inner = a;\n"
            "\n"
            "\t\tret = inner;\n"
            "\t}\n"
            "\treturn ret;\n"
            "}\n"
        )
        self.assertEqual(find_declarations_after_statements(nested), [])

    def test_detector_ignores_comments_and_string_literals(self) -> None:
        noisy = (
            "static int f(void)\n"
            "{\n"
            "\tint ret = 0;\n"
            "\n"
            '\tpr_info("int shadow;\n");\n'
            "\t/* int commented; */\n"
            "\treturn ret;\n"
            "}\n"
        )
        self.assertEqual(find_declarations_after_statements(noisy), [])

    def test_detector_ignores_struct_definitions_at_file_scope(self) -> None:
        definition = (
            "struct abk_fido_queue {\n"
            "\tspinlock_t lock;\n"
            "\tstruct {\n"
            "\t\tbool present;\n"
            "\t\tu8 id[32];\n"
            "\t} exclude[8];\n"
            "\tunsigned int exclude_count;\n"
            "};\n"
        )
        self.assertEqual(find_declarations_after_statements(definition), [])

    def test_detector_allows_multiline_initializers_before_declarations(self) -> None:
        # A brace-spanning initializer is still a declaration, not a statement.
        argv = (
            "static void f(void)\n"
            "{\n"
            "\tstatic char *argv[] = {\n"
            '\t\t"/system/bin/am",\n'
            "\t\tNULL,\n"
            "\t};\n"
            "\tint ret;\n"
            "\n"
            "\tret = call_usermodehelper(argv[0]);\n"
            "}\n"
        )
        self.assertEqual(find_declarations_after_statements(argv), [])

    def test_detector_allows_declaration_macros_before_declarations(self) -> None:
        macro = (
            "static int f(size_t len)\n"
            "{\n"
            "\tstruct crypto_skcipher *tfm;\n"
            "\tDECLARE_CRYPTO_WAIT(wait);\n"
            "\tstruct scatterlist sg;\n"
            "\tu8 iv[16] = {};\n"
            "\tint ret;\n"
            "\n"
            "\tif (!len)\n"
            "\t\treturn -EINVAL;\n"
            "\treturn ret;\n"
            "}\n"
        )
        self.assertEqual(find_declarations_after_statements(macro), [])

    def test_detector_allows_computed_array_bounds_before_declarations(self) -> None:
        # An array bound may contain a call-like expression; the declaration must
        # not be mistaken for a statement, or every later local is flagged.
        computed = (
            "static int f(void)\n"
            "{\n"
            "\tu8 inner_payload[128];\n"
            "\tu8 response_payload[1 + sizeof(inner_payload)];\n"
            "\tu8 nested[ARRAY_SIZE(response_payload[0])];\n"
            "\tint ret;\n"
            "\n"
            "\tret = g(response_payload, nested);\n"
            "\treturn ret;\n"
            "}\n"
        )
        self.assertEqual(find_declarations_after_statements(computed), [])

    def test_detector_still_flags_calls_before_declarations(self) -> None:
        # The bracket blanking must not swallow a real statement.
        broken = (
            "static int f(void)\n"
            "{\n"
            "\tret = memset(buf[0], 0, sizeof(buf));\n"
            "\tint ret;\n"
            "\n"
            "\treturn ret;\n"
            "}\n"
        )
        self.assertEqual([line for line, _ in find_declarations_after_statements(broken)], [4])


if __name__ == "__main__":
    unittest.main()
