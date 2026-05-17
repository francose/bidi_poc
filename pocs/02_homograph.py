"""
PoC: Homograph / Unicode Confusable Attack

Many Unicode characters look identical to ASCII letters but have different
code points. They:
    - render the same way in browsers, terminals, and code editors
    - hash differently
    - compare unequal under `==`
    - are accepted as Python identifiers (PEP 3131)

This PoC demonstrates two impacts:
    1. Identifier shadow: Python accepts Cyrillic 'а' (U+0430) in a name,
       creating a *second* variable that visually duplicates a Latin one.
    2. Phishing domain pair: paypal.com vs paypаl.com — eyeballing them
       is unreliable; only the hex tells you.

Run:
    python pocs/02_homograph.py
"""

from __future__ import annotations

import unicodedata
from typing import Iterable

# Identifier shadow — two variables that look identical, aren't
admin = False        # Latin 'a'
аdmin = True         # Cyrillic 'а' (U+0430)

LOOKALIKES: dict[str, str] = {
    "a": "а",   # U+0430 Cyrillic
    "e": "е",   # U+0435 Cyrillic
    "o": "о",   # U+043E Cyrillic
    "p": "р",   # U+0440 Cyrillic
    "c": "с",   # U+0441 Cyrillic
    "x": "х",   # U+0445 Cyrillic
    "y": "у",   # U+0443 Cyrillic
    "i": "і",   # U+0456 Cyrillic
    "l": "ӏ",   # U+04CF Cyrillic
}


def codepoint_dump(label: str, s: str) -> None:
    print(f"  {label:<14} {s!r}")
    for ch in s:
        print(f"    {ch!r:6}  U+{ord(ch):04X}  {unicodedata.name(ch, '?')}")
    print()


def confuse(domain: str) -> str:
    """Produce a visually-identical lookalike by swapping ASCII chars."""
    out = []
    for ch in domain:
        out.append(LOOKALIKES.get(ch, ch))
    return "".join(out)


def normalize_check(a: str, b: str) -> None:
    nfkc_a = unicodedata.normalize("NFKC", a)
    nfkc_b = unicodedata.normalize("NFKC", b)
    print(f"  raw equal:    {a == b}")
    print(f"  NFKC equal:   {nfkc_a == nfkc_b}    (still false — NFKC doesn't")
    print(f"                                       merge Cyrillic/Latin)")
    print()


def main() -> int:
    print("=" * 72)
    print("Part 1 — Identifier shadow")
    print("=" * 72)
    print(f"  admin (Latin)   = {admin}")
    print(f"  аdmin (Cyrillic)= {аdmin}")
    print(f"  visually:         {('admin', 'аdmin')!r}")
    print(f"  same object?      {id(admin) == id(аdmin)}")
    print(f"  globals() keys:   {[k for k in globals() if 'dmin' in k]}")
    print()

    print("=" * 72)
    print("Part 2 — Phishing domain pair")
    print("=" * 72)
    legit = "paypal.com"
    fake = confuse(legit)
    print(f"  legit:    {legit}")
    print(f"  fake:     {fake}    <- looks identical, different bytes")
    print()
    codepoint_dump("legit chars:", legit)
    codepoint_dump("fake chars:", fake)
    normalize_check(legit, fake)

    print("=" * 72)
    print("Part 3 — Mitigations")
    print("=" * 72)
    print("  - For identifiers: enable a linter rule (ruff: PLR2044 / RUF001)")
    print("  - For domains: use IDNA / punycode comparison (idna.encode)")
    print("  - For login flows: normalize NFKC + map confusables via")
    print("    unicodedata + a confusables table (Unicode Security Standard")
    print("    UTS #39 skeleton algorithm)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
