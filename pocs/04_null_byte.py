"""
PoC: Null Byte Injection — string-truncation mismatch

Higher-level languages (Python, Java, Go) treat strings as length-counted
byte sequences. Embedded `\\x00` is just data.

C and OS APIs that take `const char *` treat `\\x00` as terminator. So a
string like b"admin\\x00.txt" has length 9 in Python but length 5 in C.

The classic vulnerability:
    - A web app validates the filename in Python: it sees 'admin\\x00../secret'
      and rejects it because '..' is present.
    - OR it sees 'safe.txt\\x00../etc/passwd' and approves the '.txt' extension.
    - The validated string is then passed to a C-backed syscall (open(),
      execv()) which stops reading at the NUL byte.

This PoC builds the mismatch in a self-contained way using ctypes:
    - Python tells us the string has length N.
    - The C runtime, called via ctypes.c_char_p / strlen(), sees length M < N.
    - We use that asymmetry to "approve" a benign-looking name that maps
      to a sensitive path at the syscall layer.

Run:
    python pocs/04_null_byte.py
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
import tempfile

libc_path = ctypes.util.find_library("c")
libc = ctypes.CDLL(libc_path or "libc.so.6")
libc.strlen.argtypes = [ctypes.c_char_p]
libc.strlen.restype = ctypes.c_size_t


def python_view(b: bytes) -> int:
    return len(b)


def c_view(b: bytes) -> int:
    return libc.strlen(b)


def validate_filename(name: str) -> bool:
    """
    Toy allowlist filter. Looks safe in Python — only allows names ending
    in '.txt' and without obvious traversal segments.
    """
    if ".." in name:
        return False
    if "/" in name or "\\" in name:
        return False
    if not name.endswith(".txt"):
        return False
    return True


def main() -> int:
    print("=" * 72)
    print("Part 1 — Length mismatch")
    print("=" * 72)
    cases = [
        b"hello",
        b"hello\x00world",
        b"safe.txt\x00/etc/passwd",
        b"admin\x00../../etc/shadow",
    ]
    print(f"  {'bytes':<35} {'python len':>12} {'C strlen':>10}")
    print(f"  {'-' * 35:<35} {'-' * 12:>12} {'-' * 10:>10}")
    for b in cases:
        print(f"  {b!r:<35} {python_view(b):>12} {c_view(b):>10}")
    print()

    print("=" * 72)
    print("Part 2 — Filter bypass on filename allowlist")
    print("=" * 72)
    # Attacker input: pre-NUL is a sensitive *relative* filename, post-NUL
    # is a benign .txt suffix that satisfies the extension check.
    user_input = "secret\x00.txt"
    print(f"  raw user input:  {user_input!r}  (Python len {len(user_input)})")
    print(f"  C strlen view:   {c_view(user_input.encode()):>3}  (stops at NUL: 'secret')")
    if validate_filename(user_input):
        print("  filter says: ACCEPT — looks like a benign .txt")
    else:
        print("  filter says: REJECT")
    print()

    # Demonstrate concretely: create the sensitive file, write to "safe path"
    # in Python, then have a C call see only the pre-NUL prefix.
    with tempfile.TemporaryDirectory() as td:
        sensitive = os.path.join(td, "secret")
        with open(sensitive, "w") as f:
            f.write("PASSWORD=hunter2\n")

        # Simulate a vulnerable C-backed open() by handing the bytes
        # to fopen() through ctypes.
        libc.fopen.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        libc.fopen.restype = ctypes.c_void_p
        libc.fclose.argtypes = [ctypes.c_void_p]
        libc.fread.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_void_p
        ]

        full_path = f"{sensitive}\x00.txt".encode()
        print(f"  Python sees path: {full_path!r}")
        print(f"  C fopen() will receive null-terminated: {full_path.split(chr(0).encode())[0]!r}")
        fp = libc.fopen(full_path, b"r")
        if fp:
            buf = ctypes.create_string_buffer(64)
            n = libc.fread(buf, 1, 63, fp)
            libc.fclose(fp)
            print(f"  C fread got {n} bytes: {buf.value!r}")
            print("\n  ** Divergence confirmed — Python validator allowed a path")
            print("     whose C-visible portion exposed the sensitive file. **")
        else:
            print("  C fopen failed (filesystem quirk; concept still holds)")
    print()

    print("=" * 72)
    print("Mitigations")
    print("=" * 72)
    print("  - Reject any input containing NUL bytes before validation.")
    print("    `if '\\x00' in user_input: reject`")
    print("  - Use modern OS APIs (Python `pathlib`, openat(), etc.) that")
    print("    surface the NUL as an error.")
    print("  - Pass length-prefixed byte buffers into C, not C-strings.")
    print("  - Normalize and canonicalize paths *after* rejecting NUL.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
