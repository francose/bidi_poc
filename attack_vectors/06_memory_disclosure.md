# Memory Disclosure via Encoding Mismatch

## Mechanism
This vulnerability allows an attacker to read sensitive data from memory by exploiting a mismatch between the allocated buffer size and the actual size of the encoded data.

## The Vulnerability
It is the inverse of a buffer overflow.
1.  **Allocation**: Buffer is allocated based on character count (e.g., 5 chars).
2.  **Encoding**: Data is encoded into a larger format (e.g., UTF-32, 20 bytes).
3.  **Read**: The application reads back the buffer assuming the larger size, but the buffer was only allocated for the smaller size.

*Note: This specific scenario is rarer than overflow but conceptually similar to Heartbleed.*

## Real-Life Example: The "Heartbleed" Vulnerability (Conceptual Cousin)

While Heartbleed (CVE-2014-0160) was technically a missing bounds check on a length field, the principle is identical to encoding size mismatches: **Trusting a length value that contradicts the actual data size.**

### The Scenario
OpenSSL's heartbeat extension allows a client to send a payload and ask the server to echo it back to verify the connection is alive.

### The Protocol
1.  **Client sends**: "Bird" (4 bytes) AND says "Payload Length: 4".
2.  **Server replies**: "Bird".

### The Attack
1.  **Client sends**: "Bird" (4 bytes) BUT says "Payload Length: 65535".
2.  **Server Logic**:
    - Allocates a response buffer of 65535 bytes.
    - Copies the input payload into it.
    - `memcpy(response, input_ptr, payload_length_from_packet)`
3.  **The Bug**: The server didn't check if the *actual* input was 65535 bytes long. It just trusted the number.
4.  **Result**:
    - It copies "Bird" (4 bytes).
    - It continues copying the next 65531 bytes from the heap (memory adjacent to "Bird").
    - This memory contained SSL private keys, user passwords, and session cookies.

### Encoding Variant (Hypothetical)
If a server allocated memory based on `strlen(input)` (bytes) but read back based on `utf32_len(input)` (chars * 4), and the input was malicious, it could read past the buffer end.

## Impact
- **Data Leakage**: Exposure of session tokens, private keys, or PII (Personally Identifiable Information).

## Mitigation
- **Bounds Checking**: Ensure read operations never exceed the allocated buffer size.
- **Length Consistency**: Verify that the length of the data matches the length field provided in the protocol.
- **Memory Zeroing**: Zero out memory buffers after use so that leaks only reveal zeros, not secrets.
