# Homograph / Lookalike Attacks

## Mechanism
Homograph attacks exploit the visual similarity between different Unicode characters. An attacker registers a domain or creates a username that looks identical to a legitimate one but uses different characters (code points).

## The Vulnerability
- **Visual Similarity**: Many scripts (Cyrillic, Greek, Latin) share character shapes.
- **IDN (Internationalized Domain Names)**: Allows non-ASCII characters in domain names.

## Real-Life Example: The "Apple" IDN Attack

### The Scenario
In 2017, researcher Xudong Zheng demonstrated a flaw in how browsers handled IDN (Internationalized Domain Names). He registered a domain that looked exactly like `apple.com` in the address bar.

### The Attack
1.  **Target**: `apple.com`
2.  **Attacker Domain**: `xn--80ak6aa92e.com` (Punycode)
3.  **Decoding**:
    - The Punycode decodes to: `аpple.com`
    - Wait, look closer: The `а` is NOT Latin 'a' (U+0061).
    - It is Cyrillic Small Letter A (U+0430).
4.  **Browser Rendering**:
    - Chrome and Firefox (at the time) rendered it as `apple.com`.
    - The SSL certificate was valid (issued for `xn--80ak6aa92e.com`).
    - Users saw a green lock and "apple.com".

## Common Lookalikes (Confusables)

| Latin Char | Code Point | Lookalike Char | Code Point | Script |
|------------|------------|----------------|------------|--------|
| a          | U+0061     | а              | U+0430     | Cyrillic|
| c          | U+0063     | с              | U+0441     | Cyrillic|
| e          | U+0065     | е              | U+0435     | Cyrillic|
| o          | U+006F     | ο              | U+03BF     | Greek   |
| p          | U+0070     | р              | U+0440     | Cyrillic|
| x          | U+0078     | х              | U+0445     | Cyrillic|
| y          | U+0079     | у              | U+0443     | Cyrillic|

## Impact
- **Phishing**: Users trust malicious sites.
- **Social Engineering**: Impersonating admins or trusted users in chat systems.
- **Logic Errors**: Bypassing username blocklists (e.g., "admin" vs "аdmin").

## Mitigation
- **Punycode Display**: Browsers now often display the Punycode version (`xn--...`) if the domain contains characters from mixed scripts or suspicious sets.
- **Normalization**: Convert strings to a standard form (NFKC) before comparison, though this doesn't solve all visual spoofing.
- **Confusable Detection**: Use libraries that check for mixed-script usage (e.g., Latin mixed with Cyrillic is usually suspicious).
