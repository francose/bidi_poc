"""
Defender tool: scan source files for bidi controls, zero-width characters,
and ASCII-confusable Unicode letters.

What it catches:
    - Bidi controls (U+202A..U+202E, U+2066..U+2069) — Trojan Source
    - Zero-width chars (ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, WJ U+2060,
      ZWNBSP/BOM U+FEFF) — invisible payloads, source-code smuggling
    - ASCII-confusable letters from Cyrillic / Greek / etc. — homograph
      identifiers and string literals

Usage:
    python pocs/99_detect_bidi.py PATH [PATH ...]
    python pocs/99_detect_bidi.py --self-test

Exit code:
    0  no findings
    1  at least one finding (CI-friendly)
    2  usage error
"""

from __future__ import annotations

import argparse
import sys
import unicodedata
from pathlib import Path

BIDI = {
    0x202A: "LRE",
    0x202B: "RLE",
    0x202C: "PDF",
    0x202D: "LRO",
    0x202E: "RLO",
    0x2066: "LRI",
    0x2067: "RLI",
    0x2068: "FSI",
    0x2069: "PDI",
}

ZERO_WIDTH = {
    0x200B: "ZWSP",
    0x200C: "ZWNJ",
    0x200D: "ZWJ",
    0x2060: "WJ",
    0xFEFF: "BOM/ZWNBSP",
}

# A small confusables table — the subset most often weaponized against
# ASCII identifiers and domain names. For production use see the Unicode
# UTS #39 skeleton tables (the `confusable_homoglyphs` package wraps these).
CONFUSABLES = {
    "а": "a",  # U+0430 Cyrillic
    "е": "e",  # U+0435 Cyrillic
    "о": "o",  # U+043E Cyrillic
    "р": "p",  # U+0440 Cyrillic
    "с": "c",  # U+0441 Cyrillic
    "у": "y",  # U+0443 Cyrillic
    "х": "x",  # U+0445 Cyrillic
    "і": "i",  # U+0456 Cyrillic
    "ӏ": "l",  # U+04CF Cyrillic
    "Α": "A",  # U+0391 Greek
    "Β": "B",  # U+0392 Greek
    "Ε": "E",  # U+0395 Greek
    "Η": "H",  # U+0397 Greek
    "Ι": "I",  # U+0399 Greek
    "Κ": "K",  # U+039A Greek
    "Μ": "M",  # U+039C Greek
    "Ν": "N",  # U+039D Greek
    "Ο": "O",  # U+039F Greek
    "Ρ": "P",  # U+03A1 Greek
    "Τ": "T",  # U+03A4 Greek
    "Υ": "Y",  # U+03A5 Greek
    "Χ": "X",  # U+03A7 Greek
}


def scan_text(text: str) -> list[tuple[int, int, str, str, str]]:
    """
    Return a list of findings:
        (line_no, col_no, category, code_point_hex, description)
    """
    findings = []
    for li, line in enumerate(text.splitlines(), start=1):
        for ci, ch in enumerate(line, start=1):
            cp = ord(ch)
            if cp in BIDI:
                findings.append((li, ci, "BIDI", f"U+{cp:04X}", BIDI[cp]))
            elif cp in ZERO_WIDTH:
                findings.append((li, ci, "ZERO-WIDTH", f"U+{cp:04X}", ZERO_WIDTH[cp]))
            elif ch in CONFUSABLES:
                ascii_lookalike = CONFUSABLES[ch]
                name = unicodedata.name(ch, "?")
                findings.append((
                    li, ci, "CONFUSABLE", f"U+{cp:04X}",
                    f"{name} looks like ASCII {ascii_lookalike!r}",
                ))
    return findings


def scan_file(path: Path) -> list[tuple[int, int, str, str, str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []  # binary or non-utf-8 — skip silently
    return scan_text(text)


def iter_targets(paths: list[Path]):
    for p in paths:
        if p.is_dir():
            yield from (f for f in p.rglob("*") if f.is_file())
        elif p.is_file():
            yield p


def print_findings(path: Path, findings: list[tuple]) -> None:
    for li, ci, cat, hex_, desc in findings:
        print(f"  {path}:{li}:{ci}  [{cat}]  {hex_}  {desc}")


def self_test() -> int:
    samples = [
        ("clean code", "x = 1\nreturn x\n", 0),
        ("bidi RLO",   "x = 1  # ‮ bad ⁦\n", 2),
        ("zero-width", "secret = 'p​a​s​s'\n", 3),
        ("confusable", "аdmin = True\n", 1),  # Cyrillic 'а'
    ]
    failed = 0
    print("self-test:")
    for label, text, expected in samples:
        got = len(scan_text(text))
        status = "ok" if got == expected else "FAIL"
        if status == "FAIL":
            failed += 1
        print(f"  {status:<4} {label:<14} expected={expected} got={got}")
    return failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan source files for bidi/zero-width/homograph characters.",
    )
    parser.add_argument("paths", nargs="*", type=Path, help="files or directories")
    parser.add_argument("--self-test", action="store_true", help="run built-in tests and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return 1 if self_test() else 0

    if not args.paths:
        parser.print_usage()
        return 2

    total = 0
    for f in iter_targets(args.paths):
        findings = scan_file(f)
        if findings:
            print_findings(f, findings)
            total += len(findings)

    if total:
        print(f"\n{total} finding(s) across the scanned tree.")
        return 1
    print("clean — no bidi / zero-width / confusable characters found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
