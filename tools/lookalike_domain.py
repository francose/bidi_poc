"""
lookalike_domain — generate visually-equivalent variants of a target
domain for phishing-infrastructure research, brand-protection sweeps,
and IDN homograph studies.

Stdlib only. Output: one candidate per line, with the punycode form
when the candidate contains non-ASCII characters.

Strategies covered:
    homograph     swap ASCII letters for Cyrillic / Greek lookalikes
                  (one swap at a time -> N candidates)
    homograph-mix multiple positions swapped at once (bounded)
    typo-omit     drop one character (paypal -> paypl)
    typo-swap     swap two adjacent characters (paypal -> payapl)
    typo-double   double one character (paypal -> paaypal)
    typo-replace  replace one char with a keyboard neighbour
    tld-swap      swap the TLD (paypal.com -> paypal.co, .net, .org,
                  .com.co, .support, etc.)
    bitsquat      single-bit flips on each byte (paypal -> qaypal)
    hyphenate     insert hyphens (paypal -> pay-pal)

Each candidate is emitted with its puny-encoded form (xn--...) so you
can feed the output directly to a DNS resolver / WHOIS / cert-transparency
search.

Usage:
    python tools/lookalike_domain.py paypal.com
    python tools/lookalike_domain.py example.com --only homograph,typo-omit
    python tools/lookalike_domain.py example.com --csv > candidates.csv
"""

from __future__ import annotations

import argparse
import itertools
import sys

HOMOGRAPHS = {
    "a": ["а"],            # U+0430
    "b": ["Ь", "ƅ"],       # U+042C, U+0185
    "c": ["с", "ϲ"],       # U+0441, U+03F2
    "d": ["ԁ"],            # U+0501
    "e": ["е", "ε"],       # U+0435, U+03B5
    "g": ["ɡ"],            # U+0261
    "h": ["һ"],            # U+04BB
    "i": ["і", "ӏ", "ı"],  # U+0456, U+04CF, U+0131
    "j": ["ј"],            # U+0458
    "k": ["κ", "к"],       # U+03BA, U+043A
    "l": ["ӏ", "1", "I"],
    "m": ["м"],
    "n": ["п", "ո"],
    "o": ["о", "ο", "0"],  # U+043E, U+03BF, ASCII zero
    "p": ["р", "ρ"],       # U+0440, U+03C1
    "q": ["ԛ"],
    "r": ["г"],
    "s": ["ѕ"],            # U+0455
    "t": ["т"],
    "u": ["υ", "ս"],
    "v": ["ν"],
    "w": ["ԝ"],
    "x": ["х", "χ"],
    "y": ["у", "γ"],
    "z": ["ʐ"],
}

KEYBOARD_NEIGHBOURS = {
    "q": "wa",  "w": "qeas",  "e": "wrds",  "r": "etfd",  "t": "rygf",
    "y": "tuhg",  "u": "yijh",  "i": "uokj",  "o": "iplk",  "p": "ol",
    "a": "qwsz",  "s": "awedxz",  "d": "serfcx",  "f": "drtgvc",
    "g": "ftyhbv",  "h": "gyujnb",  "j": "huikmn",  "k": "jiolm,",
    "l": "kop,.", "z": "asx",  "x": "zsdc",  "c": "xdfv",  "v": "cfgb",
    "b": "vghn",  "n": "bhjm",  "m": "njk,",
}

TLD_VARIANTS = [
    "com", "co", "net", "org", "io", "support", "help", "login",
    "secure", "info", "biz", "co.uk", "com.co", "com.br",
]


def split_domain(d: str) -> tuple[str, str]:
    """Return (label, tld) — supports multi-part TLDs like co.uk."""
    parts = d.lower().split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "ac", "gov", "edu", "org"}:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return ".".join(parts[:-1]), parts[-1]


def to_idna(s: str) -> str:
    """
    Encode a domain to IDNA (puny). If it's already ASCII, return as-is.
    Uses Python's built-in idna codec (per-label).
    """
    try:
        return s.encode("idna").decode("ascii")
    except UnicodeError:
        # Some chars can't be IDNA-encoded (e.g. mixed scripts without
        # the prefix). Fall back to manual xn-- per label.
        labels = []
        for label in s.split("."):
            if label.isascii():
                labels.append(label)
            else:
                try:
                    labels.append(label.encode("idna").decode("ascii"))
                except UnicodeError:
                    labels.append("[idna-error:" + label + "]")
        return ".".join(labels)


def gen_homograph(label: str, max_swaps: int) -> set[str]:
    """Replace ASCII chars with one or more confusables (bounded combos)."""
    out: set[str] = set()
    indices = [i for i, c in enumerate(label) if c in HOMOGRAPHS]
    # Single swaps
    for i in indices:
        for sub in HOMOGRAPHS[label[i]]:
            out.add(label[:i] + sub + label[i + 1:])
    # Multi swaps up to max_swaps (avoid combinatorial blow-up)
    if max_swaps > 1 and len(indices) >= 2:
        for combo in itertools.combinations(indices, min(max_swaps, len(indices))):
            for picks in itertools.product(*(HOMOGRAPHS[label[i]] for i in combo)):
                chars = list(label)
                for i, sub in zip(combo, picks):
                    chars[i] = sub
                out.add("".join(chars))
    return out


def gen_typo_omit(label: str) -> set[str]:
    return {label[:i] + label[i + 1:] for i in range(len(label))}


def gen_typo_swap(label: str) -> set[str]:
    return {
        label[:i] + label[i + 1] + label[i] + label[i + 2:]
        for i in range(len(label) - 1)
    }


def gen_typo_double(label: str) -> set[str]:
    return {label[:i] + label[i] + label[i:] for i in range(len(label))}


def gen_typo_replace(label: str) -> set[str]:
    out = set()
    for i, c in enumerate(label):
        for n in KEYBOARD_NEIGHBOURS.get(c, ""):
            out.add(label[:i] + n + label[i + 1:])
    return out


def gen_tld_swap(label: str, tld: str) -> set[str]:
    return {f"{label}.{t}" for t in TLD_VARIANTS if t != tld}


def gen_bitsquat(label: str) -> set[str]:
    out = set()
    for i, c in enumerate(label):
        for bit in range(7):  # ASCII range only
            flipped = ord(c) ^ (1 << bit)
            if 0x20 < flipped < 0x7F:
                out.add(label[:i] + chr(flipped) + label[i + 1:])
    return out


def gen_hyphenate(label: str) -> set[str]:
    return {label[:i] + "-" + label[i:] for i in range(1, len(label))}


STRATEGIES = {
    "homograph":      lambda l, t: gen_homograph(l, 1),
    "homograph-mix":  lambda l, t: gen_homograph(l, 3),
    "typo-omit":      lambda l, t: gen_typo_omit(l),
    "typo-swap":      lambda l, t: gen_typo_swap(l),
    "typo-double":    lambda l, t: gen_typo_double(l),
    "typo-replace":   lambda l, t: gen_typo_replace(l),
    "tld-swap":       lambda l, t: gen_tld_swap(l, t),
    "bitsquat":       lambda l, t: gen_bitsquat(l),
    "hyphenate":      lambda l, t: gen_hyphenate(l),
}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Generate phishing-relevant lookalike domain variants.",
    )
    p.add_argument("domain", help="target domain (e.g. paypal.com)")
    p.add_argument("-o", "--only", help="comma-separated strategies to include")
    p.add_argument("--csv", action="store_true", help="CSV output: strategy,candidate,idna")
    p.add_argument(
        "--list-strategies", action="store_true", help="list strategy names and exit",
    )
    args = p.parse_args(argv)

    if args.list_strategies:
        for s in STRATEGIES:
            print(s)
        return 0

    label, tld = split_domain(args.domain)
    only = [s.strip() for s in args.only.split(",")] if args.only else list(STRATEGIES)
    seen: set[str] = set()

    if args.csv:
        print("strategy,candidate,idna")

    for strat in only:
        if strat == "tld-swap":
            candidates = STRATEGIES[strat](label, tld)
        else:
            raw_labels = STRATEGIES[strat](label, tld)
            candidates = {f"{lbl}.{tld}" for lbl in raw_labels if lbl}
        for cand in sorted(candidates):
            if cand == args.domain or cand in seen:
                continue
            seen.add(cand)
            idna = to_idna(cand)
            if args.csv:
                print(f"{strat},{cand},{idna}")
            else:
                marker = f"   -> {idna}" if idna != cand else ""
                print(f"{cand}{marker}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
