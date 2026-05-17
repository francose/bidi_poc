"""
PoC: UTF-8 Overlong Encoding — filter bypass

UTF-8 specifies a single canonical byte sequence for each code point. Many
old or hand-rolled decoders also accept *overlong* multi-byte sequences
that encode the same code point in more bytes than necessary. The
canonical example is the '/' character (U+002F):

    Canonical:   0x2F                       (1 byte)
    Overlong:    0xC0 0xAF                  (2 bytes, INVALID)
    Overlong:    0xE0 0x80 0xAF             (3 bytes, INVALID)
    Overlong:    0xF0 0x80 0x80 0xAF        (4 bytes, INVALID)

Real-world impact: a security filter (allowlist of safe chars, blocklist
of '../') validates the raw byte sequence, doesn't see a '/', and passes
the input. A more permissive downstream decoder then normalizes the
overlong form to '/' — and you get directory traversal.

Famous instance: IIS Unicode Directory Traversal (CVE-2000-0884) —
Microsoft IIS decoded overlong UTF-8 sequences while the URL filter
didn't, allowing `..%C0%AF..%C0%AF..%C0%AFwinnt%2fsystem32%2fcmd.exe`.

This PoC:
    1. Encodes '/' four ways (canonical + three overlong widths).
    2. Shows that Python's `str.decode('utf-8')` rejects the overlong
       sequences in *strict* mode (correct), but a custom "permissive"
       decoder accepts them — modelling a vulnerable downstream.
    3. Demonstrates the gap by checking a path through both decoders.

Run:
    python pocs/03_overlong_utf8.py
"""

from __future__ import annotations

CANONICAL = bytes([0x2F])
OVERLONG_2 = bytes([0xC0, 0xAF])
OVERLONG_3 = bytes([0xE0, 0x80, 0xAF])
OVERLONG_4 = bytes([0xF0, 0x80, 0x80, 0xAF])

PAYLOAD = b"scripts\xC0\xAF..\xC0\xAF..\xC0\xAFwinnt\xC0\xAFsystem32\xC0\xAFcmd.exe"


def show_strict_decode(label: str, b: bytes) -> None:
    try:
        decoded = b.decode("utf-8")
        verdict = f"OK -> {decoded!r}"
    except UnicodeDecodeError as e:
        verdict = f"REJECTED ({e.reason})"
    print(f"  {label:<22} {b.hex(' '):<14}  strict utf-8: {verdict}")


def permissive_decode(b: bytes) -> str:
    """
    Naive decoder that accepts overlong sequences (models a vulnerable
    legacy decoder). For each leading byte it reads the declared number
    of continuation bytes and assembles the code point with no overlong
    check, no surrogate check, no max-codepoint check.
    """
    out: list[str] = []
    i = 0
    while i < len(b):
        first = b[i]
        if first < 0x80:
            out.append(chr(first))
            i += 1
            continue
        if first & 0xE0 == 0xC0:
            n = 1; cp = first & 0x1F
        elif first & 0xF0 == 0xE0:
            n = 2; cp = first & 0x0F
        elif first & 0xF8 == 0xF0:
            n = 3; cp = first & 0x07
        else:
            out.append("?"); i += 1; continue
        for j in range(1, n + 1):
            cp = (cp << 6) | (b[i + j] & 0x3F)
        out.append(chr(cp))
        i += n + 1
    return "".join(out)


def looks_safe(b: bytes) -> bool:
    """
    Toy filter modelling the original IIS check: block any request whose
    raw bytes contain '/' or '\\'. (Real filters look at more, but this
    matches the historic vulnerability class.)
    """
    return b"/" not in b and b"\\" not in b


def main() -> int:
    print("=" * 72)
    print("Part 1 — Four encodings of '/' (only one is valid UTF-8)")
    print("=" * 72)
    show_strict_decode("canonical 1-byte", CANONICAL)
    show_strict_decode("overlong 2-byte",  OVERLONG_2)
    show_strict_decode("overlong 3-byte",  OVERLONG_3)
    show_strict_decode("overlong 4-byte",  OVERLONG_4)
    print()

    print("=" * 72)
    print("Part 2 — Filter bypass (IIS-style): overlong '/' inside a path")
    print("=" * 72)
    print(f"  raw payload bytes: {PAYLOAD.hex(' ')}")
    has_slash = (b"/" in PAYLOAD) or (b"\\" in PAYLOAD)
    print(f"  contains literal '/' or backslash? -> {has_slash}")
    print(f"  filter says: {'SAFE — pass through' if looks_safe(PAYLOAD) else 'BLOCK'}")
    print()

    print("  strict utf-8 decode:     ", end="")
    try:
        print(repr(PAYLOAD.decode("utf-8")))
    except UnicodeDecodeError as e:
        print(f"REJECTED ({e.reason})  <- safe backend behavior")

    permissive = permissive_decode(PAYLOAD)
    print(f"  permissive decode:        {permissive!r}")
    print()
    print("  ** The toy filter passed the raw bytes because no literal '/' was")
    print("     present. A legacy decoder then normalized them to '/'. Result:")
    print(f"     attacker-controlled path -> {permissive!r}")
    print()

    print("=" * 72)
    print("Mitigations")
    print("=" * 72)
    print("  - Decode UTF-8 in strict mode FIRST, then validate the result.")
    print("    Order matters: canonicalize before authorizing.")
    print("  - Reject overlong sequences explicitly (Python's strict decoder")
    print("    already does this).")
    print("  - Map characters via unicodedata.normalize('NFKC', s) before")
    print("    string comparison.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
