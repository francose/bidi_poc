# Buffer Overflow Attacks via Encoding Mismatch

## Mechanism
This attack occurs when a program allocates memory based on the size of one encoding (usually a compact one like UTF-8 or ASCII) but writes data using a larger encoding (like UTF-32), causing a buffer overflow.

## The Vulnerability
1.  **Allocation**: The application calculates buffer size based on `len(string)`. In many languages, this returns the number of characters, not bytes.
2.  **Assumption**: The developer assumes 1 char = 1 byte (ASCII/UTF-8).
3.  **Execution**: The application receives input, converts it to a fixed-width encoding (like UTF-32 for internal processing), and writes it to the buffer.

## Real-Life Example: C++ Username Processing

### The Scenario
A legacy C++ server handles user logins. It uses a library that converts usernames to UTF-32 (`wchar_t` on Linux is often 4 bytes) for internal processing but calculates buffer size using a standard string length function.

### The Vulnerable Code
```cpp
void process_username(char* utf8_input) {
    // 1. Calculate length (Counts CHARACTERS, not bytes)
    // If input is "héllo" (5 chars), len = 5
    size_t len = g_utf8_strlen(utf8_input, -1); 
    
    // 2. Allocate buffer for wide characters (UTF-32)
    // MISTAKE: Allocating 5 * 4 = 20 bytes? 
    // NO, often the mistake is allocating 'len' bytes thinking it's enough, 
    // or allocating 'len * sizeof(wchar_t)' but forgetting the null terminator.
    
    // Let's look at the "Encoding Mismatch" variant:
    // The dev allocates based on input byte length, but expands to UTF-32.
    int input_bytes = strlen(utf8_input); // "héllo" = 6 bytes (e is 2 bytes)
    
    // Allocates 6 bytes.
    wchar_t* buffer = (wchar_t*)malloc(input_bytes); 
    
    // 3. Convert and Write
    // Converts "héllo" to UTF-32.
    // 'h' = 4 bytes
    // 'é' = 4 bytes
    // ...
    // Total needed: 5 chars * 4 bytes = 20 bytes.
    mbstowcs(buffer, utf8_input, len); 
    
    // RESULT: Writes 20 bytes into a 6-byte buffer.
    // OVERFLOW: 14 bytes overwrite adjacent memory.
}
```

## Memory Layout Visualization

```
Before Write:
┌─────────────────────┬──────────────────────────────┐
│ Buffer (5 bytes)    │ Return Address / Stack Data  │
└─────────────────────┴──────────────────────────────┘

After Writing "hello" in UTF-32 (Hex: 68 00 00 00 ...):
┌─────────────────────┬──────────────────────────────┐
│ 68 00 00 00 65      │ 00 00 00 6c 00 00 00 ...     │
└─────────────────────┴──────────────────────────────┘
  ^ Buffer ends here    ^ OVERFLOW! Return addr corrupted
```

## Impact
- **Code Execution**: Overwriting the return address can redirect program flow to attacker-controlled shellcode.
- **Crash (DoS)**: Corrupting stack data usually causes a segmentation fault.
- **Data Corruption**: Overwriting adjacent variables or flags.

## Mitigation
- **Size Calculation**: Always allocate based on `len(encoded_bytes)`, not `len(string)`.
- **Safe Functions**: Use functions that accept buffer size limits (e.g., `strncpy` instead of `strcpy`, though even `strncpy` has pitfalls).
- **Memory Safe Languages**: Use languages like Rust or Python (which handle memory management automatically), though C extensions in these languages can still be vulnerable.
