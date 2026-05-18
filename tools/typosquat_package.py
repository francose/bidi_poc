"""
typosquat_package — generate typosquat candidates for a package name on
PyPI / npm / RubyGems / crates.io.

Stdlib only. Output: one candidate per line (or CSV with availability
when --check is used).

Strategies are tuned for package-registry rules (which usually
case-fold, normalise separators, and reject certain characters):

    omit          drop one character (requests -> equests, rquests, ...)
    swap          swap adjacent chars (requests -> erquests)
    double        double a character (requests -> rrequests)
    replace       replace with keyboard neighbour (requests -> reauests)
    insert        insert one char from [a-z0-9_-]
    separator     hyphen<->underscore<->dot variants (PyPI normalises
                  -, _ and . to '-' for the *index*, but file names and
                  imports keep distinct forms — exploitable)
    homograph     Cyrillic / Greek lookalikes (rejected by PyPI normalisation
                  but accepted in source-code references and some legacy
                  registries; useful for documentation typo bait)
    prefix-suffix Common ecosystem prefixes/suffixes: python-, py-, lib-,
                  -ng, -js, -client, -sdk, -utils
    bitsquat      ASCII single-bit flips
    extras        ecosystem-specific: pip, npm, gem, cargo prefixes

Optional online check (--check pypi|npm) probes the registry's JSON API
to see which candidates are unregistered (lower = available).

Usage:
    python tools/typosquat_package.py requests
    python tools/typosquat_package.py react-router --only swap,separator
    python tools/typosquat_package.py requests --check pypi --csv > squats.csv
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

KEYBOARD_NEIGHBOURS = {
    "q": "wa",  "w": "qeas",  "e": "wrds",  "r": "etfd",  "t": "rygf",
    "y": "tuhg",  "u": "yijh",  "i": "uokj",  "o": "iplk",  "p": "ol",
    "a": "qwsz",  "s": "awedxz",  "d": "serfcx",  "f": "drtgvc",
    "g": "ftyhbv",  "h": "gyujnb",  "j": "huikmn",  "k": "jiolm",
    "l": "kop", "z": "asx",  "x": "zsdc",  "c": "xdfv",  "v": "cfgb",
    "b": "vghn",  "n": "bhjm",  "m": "njk",
    "-": "_",  "_": "-",  ".": "-_",
}

HOMOGRAPHS = {
    "a": "а",  "c": "с",  "e": "е",  "i": "і",  "j": "ј",  "o": "о",
    "p": "р",  "r": "г",  "s": "ѕ",  "x": "х",  "y": "у",  "h": "һ",
}

PREFIXES = ["python-", "py-", "lib-", "node-", "js-"]
SUFFIXES = ["-ng", "-js", "-client", "-sdk", "-utils", "-cli", "-py", "2"]
INSERT_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-_"


def gen_omit(name: str) -> set[str]:
    return {name[:i] + name[i + 1:] for i in range(len(name)) if name[:i] + name[i + 1:]}


def gen_swap(name: str) -> set[str]:
    return {name[:i] + name[i + 1] + name[i] + name[i + 2:] for i in range(len(name) - 1)}


def gen_double(name: str) -> set[str]:
    return {name[:i] + name[i] + name[i:] for i in range(len(name))}


def gen_replace(name: str) -> set[str]:
    out = set()
    for i, c in enumerate(name):
        for n in KEYBOARD_NEIGHBOURS.get(c, ""):
            out.add(name[:i] + n + name[i + 1:])
    return out


def gen_insert(name: str) -> set[str]:
    out = set()
    for i in range(len(name) + 1):
        for c in INSERT_CHARS:
            out.add(name[:i] + c + name[i:])
    return out


def gen_separator(name: str) -> set[str]:
    out: set[str] = set()
    seps = ["-", "_", "."]
    if any(s in name for s in seps):
        for from_s in seps:
            for to_s in seps:
                if from_s != to_s and from_s in name:
                    out.add(name.replace(from_s, to_s))
    # Also: insert a separator before each non-leading lowercase letter,
    # for camel-case-y names like "fastapi" -> "fast-api", "fast_api"
    if not any(s in name for s in seps) and len(name) >= 5:
        for split in range(2, len(name) - 1):
            for s in seps:
                out.add(name[:split] + s + name[split:])
    return out


def gen_homograph(name: str) -> set[str]:
    out = set()
    for i, c in enumerate(name):
        if c in HOMOGRAPHS:
            out.add(name[:i] + HOMOGRAPHS[c] + name[i + 1:])
    return out


def gen_prefix_suffix(name: str) -> set[str]:
    return ({pre + name for pre in PREFIXES} |
            {name + suf for suf in SUFFIXES})


def gen_bitsquat(name: str) -> set[str]:
    out = set()
    for i, c in enumerate(name):
        for bit in range(7):
            f = ord(c) ^ (1 << bit)
            if 0x20 < f < 0x7F and (chr(f).isalnum() or chr(f) in "-_."):
                out.add(name[:i] + chr(f) + name[i + 1:])
    return out


STRATEGIES = {
    "omit":          gen_omit,
    "swap":          gen_swap,
    "double":        gen_double,
    "replace":       gen_replace,
    "insert":        gen_insert,
    "separator":     gen_separator,
    "homograph":     gen_homograph,
    "prefix-suffix": gen_prefix_suffix,
    "bitsquat":      gen_bitsquat,
}


# ---- registry availability checks ------------------------------------

def check_pypi(name: str, timeout: float = 3.0) -> str:
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return "registered" if r.status == 200 else f"http-{r.status}"
    except urllib.error.HTTPError as e:
        return "available" if e.code == 404 else f"http-{e.code}"
    except Exception as e:  # noqa: BLE001
        return f"err:{type(e).__name__}"


def check_npm(name: str, timeout: float = 3.0) -> str:
    url = f"https://registry.npmjs.org/{name}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return "registered" if r.status == 200 else f"http-{r.status}"
    except urllib.error.HTTPError as e:
        return "available" if e.code == 404 else f"http-{e.code}"
    except Exception as e:  # noqa: BLE001
        return f"err:{type(e).__name__}"


CHECKERS = {"pypi": check_pypi, "npm": check_npm}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate package-name typosquat candidates.")
    p.add_argument("name", help="target package name")
    p.add_argument("-o", "--only", help="comma-separated strategies")
    p.add_argument("--check", choices=list(CHECKERS) + ["none"], default="none",
                   help="probe registry availability (slow; rate-limited)")
    p.add_argument("--csv", action="store_true", help="CSV output: strategy,candidate[,availability]")
    p.add_argument("--limit", type=int, help="cap candidates per strategy")
    p.add_argument("--list-strategies", action="store_true")
    args = p.parse_args(argv)

    if args.list_strategies:
        for s in STRATEGIES:
            print(s)
        return 0

    only = [s.strip() for s in args.only.split(",")] if args.only else list(STRATEGIES)
    seen: set[str] = set()
    rows: list[tuple[str, str]] = []  # (strategy, candidate)

    for strat in only:
        if strat not in STRATEGIES:
            print(f"[!] unknown strategy: {strat}", file=sys.stderr)
            continue
        cands = sorted(STRATEGIES[strat](args.name))
        if args.limit:
            cands = cands[:args.limit]
        for c in cands:
            if c == args.name or not c or c in seen:
                continue
            seen.add(c)
            rows.append((strat, c))

    header_extra = ",availability" if args.check != "none" else ""
    if args.csv:
        print(f"strategy,candidate{header_extra}")

    for strat, c in rows:
        availability = ""
        if args.check != "none":
            availability = CHECKERS[args.check](c)
        if args.csv:
            cells = [strat, c]
            if availability:
                cells.append(availability)
            print(",".join(cells))
        else:
            tag = f"   [{availability}]" if availability else ""
            print(f"{c}{tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
