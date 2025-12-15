# UTF-8 Overlong Encoding Attack

## Mechanism
Overlong encoding is a technique where an ASCII character is represented using more bytes than necessary in UTF-8. This is used to bypass security filters that sanitize input based on byte patterns.

## The Vulnerability
UTF-8 is variable width.
- Standard `/` (slash): `0x2F` (1 byte)
- Overlong `/`: `0xC0 0xAF` (2 bytes)
- Overlong `/`: `0xE0 0x80 0xAF` (3 bytes)

According to the standard, decoders should reject overlong sequences, but many older or permissive decoders accept them and convert them to the corresponding character.

## Real-Life Example: IIS 4.0/5.0 Directory Traversal

### The Scenario
A classic vulnerability in Microsoft IIS web servers allowed attackers to execute commands by traversing out of the web root. The server blocked standard `../` sequences but failed to block overlong representations.

### The Attack
1.  **Goal**: Execute `cmd.exe` located in `C:\WINNT\system32`.
2.  **Blocked Request**: `http://server/scripts/../../winnt/system32/cmd.exe`
    - The server checks for `../` and rejects it.
3.  **Bypass Request**: `http://server/scripts/..%c0%af../winnt/system32/cmd.exe`
    - `%c0%af` is an overlong encoding for `/` (0x2F).
    - `0xC0` = 11000000
    - `0xAF` = 10101111
    - Decoded: `00000` `101111` -> `00101111` -> `/`
4.  **Execution**:
    - The security filter did not recognize `%c0%af` as a slash.
    - The underlying file system API normalized it to a slash.
    - The path became `scripts/../../winnt/system32/cmd.exe`.
    - Code execution achieved.

## Technical Detail
UTF-8 uses prefix bits to indicate length.
- 1 byte: `0xxxxxxx`
- 2 bytes: `110xxxxx 10xxxxxx`

To encode `/` (0x2F = 00101111) as 2 bytes:
- Format: `110xxxxx 10xxxxxx`
- Distribute bits: `00000` `101111`
- Result: `11000000` `10101111` -> `C0` `AF`

## Impact
- **WAF Bypass**: Evading signature-based detection.
- **Input Validation Bypass**: Sneaking forbidden characters (like `'`, `<`, `>`) past filters to perform SQL Injection or XSS.

## Mitigation
- **Strict Decoding**: Configure UTF-8 decoders to reject overlong sequences (most modern languages do this by default).
- **Canonicalization**: Decode the input *before* applying security filters.
- **Hex Validation**: Reject specific byte sequences known to be overlong representations of dangerous characters.
