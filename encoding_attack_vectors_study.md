# Encoding Attack Vectors Study Guide

## Overview
This document covers security vulnerabilities and attack vectors related to string encoding and memory management.

---

## 1. Buffer Overflow Attacks

When a program allocates memory based on one encoding but receives data in another:

```
Expected: UTF-8 "hello" = 5 bytes buffer
Received: UTF-32 "hello" = 24 bytes → OVERFLOW!
```

### Memory Layout:
```
┌─────────────────────────────────────────────────────┐
│ Allocated Buffer (5 bytes)  │ Adjacent Memory       │
├─────────────────────────────┼───────────────────────┤
│ [h][e][l][l][o]             │ [return addr][stack]  │
└─────────────────────────────┴───────────────────────┘
                               ↑
                    Attacker overwrites this with UTF-32 data
```

### Attack Scenario:
Send UTF-32 encoded data to a function expecting UTF-8 → overflow into return address → execute malicious code.

---

## 2. Null Byte Injection

UTF-16 and UTF-32 contain `0x00` bytes between characters:

```
UTF-8:  "hello"  → 68 65 6c 6c 6f
UTF-16: "hello"  → 68 00 65 00 6c 00 6c 00 6f 00
                      ↑     ↑     ↑     ↑     ↑
                   Null bytes!
```

### Attack Example:
```python
# Attacker sends: "admin\x00.txt"
# C function sees: "admin" (stops at null byte)
# Python sees: "admin\x00.txt"

filename = "admin\x00../../etc/passwd"
# Security check sees: "admin"
# File system might see: "admin" OR full path depending on language
```

### Why This Works:
- C-style strings terminate at null byte (`\x00`)
- Higher-level languages (Python, Java) include null as part of string
- Security filters may validate truncated string while system processes full path

---

## 3. Homograph/Lookalike Attacks (Visual Spoofing)

Different Unicode characters look identical:

```
'a' (U+0061) Latin Small Letter A
'а' (U+0430) Cyrillic Small Letter A  ← LOOKS THE SAME!

'o' (U+006F) Latin Small Letter O
'ο' (U+03BF) Greek Small Letter Omicron  ← LOOKS THE SAME!
```

### Attack Example:
```
Legitimate: paypal.com
Fake:       pаypal.com  (Cyrillic 'а')
            ↑
         Different memory address, same appearance!
```

### Common Lookalikes:
| Latin | Lookalike | Script |
|-------|-----------|--------|
| a | а | Cyrillic |
| e | е | Cyrillic |
| o | ο | Greek |
| p | р | Cyrillic |
| c | с | Cyrillic |
| x | х | Cyrillic |

---

## 4. UTF-8 Overlong Encoding Attack

UTF-8 allows multiple ways to encode the same character (illegal but some parsers accept):

```
'/' (U+002F) can be encoded as:
- Valid:   0x2F                 (1 byte)
- Invalid: 0xC0 0xAF            (2 bytes - overlong)
- Invalid: 0xE0 0x80 0xAF       (3 bytes - overlong)
```

### Attack Scenario:
```python
# Attacker tries to bypass path validation:
path = "../etc/passwd"        # Blocked by security filter
path = "..\xC0\xAFetc/passwd" # Overlong '/' might bypass filter!

# Security filter sees: "..\xC0\xAF" (not recognized as "/")
# Decoder converts: "..\xC0\xAF" → "../" → PATH TRAVERSAL!
```

### Why This Works:
- Security filter doesn't recognize overlong encoding as "/"
- Backend decoder normalizes it to valid "/"
- Results in directory traversal attack

---

## 5. BOM (Byte Order Mark) Injection

UTF-16/32 use BOM to indicate byte order:

```
UTF-16 LE BOM: 0xFF 0xFE
UTF-16 BE BOM: 0xFE 0xFF
UTF-32 LE BOM: 0xFF 0xFE 0x00 0x00
```

### Attack Scenario:
```python
# Inject BOM in the middle of data to confuse parsers
malicious = b'\xff\xfemalicious_code'

# Some parsers restart decoding at BOM
# Can cause code injection or data corruption
```

### Risks:
- Parser confusion and state reset
- File type misidentification
- Code injection in XML/HTML with encoding declarations

---

## 6. Memory Disclosure via Encoding Mismatch

```python
# Server allocates based on character count
user_input = "hello"  # 5 characters
buffer = allocate(len(user_input))  # 5 bytes

# But encodes as UTF-32
encoded = user_input.encode('utf-32')  # 24 bytes!

# Reading beyond buffer leaks adjacent memory
# Similar to Heartbleed vulnerability
```

### Memory Layout:
```
┌─────────────────┬─────────────────────────────┐
│ Allocated (5B)  │ Sensitive Data (leaked)     │
├─────────────────┼─────────────────────────────┤
│ [h][e][l][l][o] │ [password][session][keys]   │
└─────────────────┴─────────────────────────────┘
         ↑                    ↑
    Buffer starts      Read continues here!
```

---

## 7. Packed Decimal Specific Attacks

### Invalid Nibble Attack:
```
Valid packed decimal: 0x12 0x3C  (123, positive)
Invalid nibble:       0x1A 0x3C  (A is not 0-9!)
```

### Risks:
- Arithmetic errors in financial calculations
- Potential for code execution in COBOL systems
- Financial calculation manipulation

### Sign Nibble Manipulation:
```
0x12 0x3C = +123
0x12 0x3D = -123  ← Flip sign by changing one nibble!

Sign nibbles:
- 0xC = positive
- 0xD = negative  
- 0xF = unsigned
```

### Attack Scenario:
Attacker modifies sign nibble in financial transaction:
- Original: $1000.00 credit (0x10 0x00 0x00 0x0C)
- Modified: $1000.00 debit  (0x10 0x00 0x00 0x0D)

---

## 8. Double Encoding Attack

```python
# Original: <script>
# URL encoded: %3Cscript%3E
# Double encoded: %253Cscript%253E

# Security filter decodes once: %3Cscript%3E (safe looking)
# Application decodes again: <script> → XSS!
```

### Encoding Layers:
```
Layer 0: <script>alert('XSS')</script>
Layer 1: %3Cscript%3Ealert('XSS')%3C/script%3E
Layer 2: %253Cscript%253Ealert('XSS')%253C/script%253E
```

### Why This Works:
1. Security filter decodes once → sees `%3Cscript%3E` (not dangerous looking)
2. Application decodes again → `<script>` executes!

---

## Summary Table

| Attack | Encoding Issue | Impact |
|--------|----------------|--------|
| Buffer Overflow | Size mismatch | Code execution |
| Null Byte Injection | UTF-16/32 nulls | Path traversal, filter bypass |
| Homograph | Unicode lookalikes | Phishing |
| Overlong UTF-8 | Invalid encoding | Filter bypass |
| BOM Injection | BOM in data | Parser confusion |
| Memory Disclosure | Encoding size mismatch | Data leak |
| Packed Decimal | Invalid nibbles | Financial fraud |
| Double Encoding | Multiple decode passes | XSS, injection |

---

## Mitigations

### 1. Always Validate Encoding
```python
try:
    text = data.decode('utf-8', errors='strict')
except UnicodeDecodeError:
    reject_input()
```

### 2. Normalize Unicode Before Comparison
```python
import unicodedata
normalized = unicodedata.normalize('NFKC', user_input)
```

### 3. Use Byte Length, Not Character Count
```python
buffer_size = len(text.encode('utf-8'))  # Not len(text)
```

### 4. Reject Overlong Sequences
Most modern parsers reject these by default. Ensure your parser is configured correctly.

### 5. Sanitize BOM from User Input
```python
if data.startswith(b'\xff\xfe') or data.startswith(b'\xfe\xff'):
    data = data[2:]  # Strip BOM
```

### 6. Use Allowlists for Characters
```python
import re
# Only allow safe characters
if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
    reject_input()
```

### 7. Validate Packed Decimal Nibbles
```python
def validate_packed_decimal(data):
    for byte in data[:-1]:  # All bytes except last
        high = (byte >> 4) & 0x0F
        low = byte & 0x0F
        if high > 9 or low > 9:
            raise ValueError("Invalid packed decimal")
    # Check last byte (contains sign)
    last = data[-1]
    high = (last >> 4) & 0x0F
    sign = last & 0x0F
    if high > 9 or sign not in [0xC, 0xD, 0xF]:
        raise ValueError("Invalid packed decimal")
```

---

## Study Questions

1. Why does UTF-16 contain null bytes that can be exploited?
2. How does encoding size difference lead to buffer overflow?
3. What is the difference between URL encoding and double encoding?
4. Why are homograph attacks difficult to detect visually?
5. How does overlong UTF-8 encoding bypass security filters?
6. What makes packed decimal vulnerable to sign manipulation?
7. How is the Heartbleed bug related to encoding length mismatches?
8. Why should you normalize Unicode before security comparisons?

---

## References

- Unicode Security Considerations: https://unicode.org/reports/tr36/
- OWASP Encoding: https://owasp.org/www-community/attacks/
- CWE-176: Improper Handling of Unicode Encoding
- CWE-180: Incorrect Behavior Order: Validate Before Canonicalize
