# Double Encoding Attack

## Mechanism
Double encoding (or multiple encoding) is an evasion technique where an attacker encodes malicious characters multiple times to bypass security filters that only decode once.

## The Vulnerability
Web applications often consist of multiple layers (WAF, Load Balancer, Web Server, Application Code, Database). If each layer decodes the input, an attacker can "wrap" the payload in layers of encoding.

## Real-Life Example: Bypassing XSS Filters

### The Scenario
A web application has a search feature. It uses a security filter (WAF or input sanitization function) to block the `<script>` tag to prevent Cross-Site Scripting (XSS).

### The Filter Logic
The filter looks for the `<` character (`%3C` in URL encoding) and blocks the request if found.

### The Attack
1.  **Goal**: Inject `<script>alert(1)</script>`
2.  **Attempt 1 (Standard)**: `search.php?q=%3Cscript%3E...`
    - Filter decodes `%3C` -> `<`.
    - Filter sees `<`. BLOCKED.
3.  **Attempt 2 (Double Encoding)**: `search.php?q=%253Cscript%253E...`
    - **Layer 1 (Filter)**:
        - Decodes `%25` -> `%`.
        - Result string: `%3Cscript%3E`
        - Does it contain `<`? No.
        - **PASSED**.
    - **Layer 2 (Application)**:
        - The application receives `%3Cscript%3E`.
        - Many web frameworks automatically decode URL parameters *again* or the developer manually calls `urldecode()`.
        - Decodes `%3C` -> `<`.
        - Result: `<script>alert(1)</script>`
        - **EXECUTED**.

## Variations
- **Double URL Encoding**: `%253C`
- **Triple URL Encoding**: `%25253C`
- **Mixed Encoding**: Combining URL encoding with HTML entities (`&lt;`) or Unicode escapes (`\u003c`).

## Impact
- **XSS (Cross-Site Scripting)**: Injecting malicious scripts.
- **SQL Injection**: Hiding quotes (`'`) or comments (`--`).
- **Path Traversal**: Hiding `../` as `%252e%252e%252f`.

## Mitigation
- **Decode Until Stable**: Recursively decode the input until it stops changing, *then* apply security filters.
- **Deny Double Encoding**: Reject requests that contain `%25` followed by hex digits if double encoding is not expected.
- **Context-Aware Output Encoding**: Instead of filtering input, encode the output properly for the context (HTML, JS, SQL) so the browser treats it as text, not code.
