# Null Byte Injection

## Mechanism
Null Byte Injection exploits the difference in how strings are terminated in low-level languages (C/C++) versus high-level languages (PHP, Python, Java).

## The Vulnerability
- **C/C++**: Strings are null-terminated. They end at the first `0x00` byte.
- **High-Level**: Strings store their length explicitly and can contain `0x00` bytes as data.
- **Encodings**: UTF-16 and UTF-32 naturally contain many `0x00` bytes (e.g., 'A' in UTF-16LE is `0x41 0x00`).

## Real-Life Example: PHP Local File Inclusion (LFI)

### The Scenario
An older web application (PHP < 5.3.4) allows users to view profiles. The code appends `.php` to the input to ensure only PHP files are loaded.

### The Vulnerable Code
```php
$page = $_GET['page']; // User input

// Security: Force extension to be .php
// Intent: Only allow loading "home.php", "profile.php"
include($page . ".php");
```

### The Attack
1.  **Attacker Input**: `../../etc/passwd%00`
2.  **PHP String**: `../../etc/passwd\0.php`
3.  **Execution**:
    - PHP passes this string to the underlying C function `open()`.
    - C sees: `../../etc/passwd` (Stops reading at `\0`).
    - The `.php` extension is effectively ignored.
4.  **Result**: The server displays the contents of `/etc/passwd`.

## Memory Representation
```
Input: "admin\x00.txt"

Memory (Hex):
61 64 6d 69 6e 00 2e 74 78 74
|---|---|---|---|--|--|--|--|--|--|
 a   d   m   i   n \0  .  t  x  t

C-String View:  [admin] (Stops at 00)
Managed View:   [admin\0.txt] (Length known)
```

## Impact
- **File System Access**: Bypassing file extension filters.
- **WAF Bypass**: Web Application Firewalls might check the full string, but the backend server processes the truncated version.

## Mitigation
- **Sanitization**: Reject strings containing null bytes (`\x00`) if they are not expected.
- **API Usage**: Use file system APIs that accept explicit lengths rather than null-terminated strings, if available.
- **Re-encoding**: Ensure the string is valid UTF-8 and does not contain unexpected nulls before passing to system calls.
