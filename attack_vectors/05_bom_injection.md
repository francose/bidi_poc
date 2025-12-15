# BOM (Byte Order Mark) Injection

## Mechanism
The Byte Order Mark (BOM) is a Unicode character (U+FEFF) placed at the start of a file to indicate endianness (byte order). Attackers inject this character in unexpected places to confuse parsers or alter data interpretation.

## The Vulnerability
- **Magic Bytes**: `0xFF 0xFE` (UTF-16LE), `0xFE 0xFF` (UTF-16BE), `0xEF 0xBB 0xBF` (UTF-8).
- **Parser Behavior**: Some parsers treat the BOM as a zero-width non-breaking space, while others reset their state or switch encoding modes when they encounter it.

## Real-Life Example: WAF Bypass via BOM

### The Scenario
A Web Application Firewall (WAF) is configured to block Cross-Site Scripting (XSS) payloads that start with `<script>`. It uses a regex anchored to the start of the string.

### The Vulnerable Regex
```regex
^<script>
```

### The Attack
1.  **Standard Attack**: `<script>alert(1)</script>`
    - Matches `^<script>`. BLOCKED.
2.  **BOM Injection**: `\xEF\xBB\xBF<script>alert(1)</script>`
    - The string starts with the UTF-8 BOM bytes.
    - It does NOT match `^<script>` (because the first char is BOM, not `<`).
    - PASSED by WAF.
3.  **Browser Execution**:
    - The browser receives the response.
    - It sees the BOM, switches to UTF-8 (or just ignores it as a zero-width space).
    - It executes the `<script>` tag immediately following.

## Impact
- **Parser Confusion**: Causing syntax errors or misinterpretation of data structure.
- **Filter Bypass**: Hiding malicious keywords behind encoding markers.
- **DoS**: Crashing parsers that don't handle mid-stream BOMs.

## Mitigation
- **Strip BOM**: Remove BOMs from the start of inputs before processing.
- **Reject Mid-stream BOMs**: Treat U+FEFF as invalid if found in the middle of a string (unless specifically allowed).
- **Enforce Encoding**: Do not rely on auto-detection; enforce a specific encoding (usually UTF-8 without BOM).
