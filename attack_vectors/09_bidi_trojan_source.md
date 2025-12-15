# Bidirectional (Bidi) Override Attacks (Trojan Source)

## Mechanism
This attack exploits Unicode Bidirectional (Bidi) control characters. These characters are designed to support languages that are written right-to-left (like Arabic or Hebrew) mixed with left-to-right text (like English).

Attackers use these characters to make source code look one way to a human reviewer, but be interpreted completely differently by the compiler or interpreter.

## The Vulnerability
- **Human View**: We read code based on how it is rendered (visual order).
- **Compiler View**: Compilers parse code based on the sequence of bytes (logical order).
- **Mismatch**: Bidi control characters change the visual order without changing the logical order.

## Common Control Characters
- `U+202E` (RLO): Right-to-Left Override (Forces text to run right-to-left)
- `U+202D` (LRO): Left-to-Right Override
- `U+2066` (LRI): Left-to-Right Isolate
- `U+2069` (PDI): Pop Directional Isolate (Ends the scope of an isolate)

## Real-Life Example: The "Trojan Source" Attack (CVE-2021-42574)

### The Scenario
In 2021, researchers discovered that most compilers (C, C++, Go, Python, Rust, etc.) ignored Unicode Bidi control characters, while code editors (VS Code, Vim, GitHub UI) respected them. This allowed attackers to create code that looked one way to a human but executed differently.

### The Attack Code (Go Example)
An attacker submits a Pull Request to a Go project.

**Visual View (What the reviewer sees):**
```go
package main

func main() {
    accessLevel := "user"
    if accessLevel != "user" { // Check if admin
        fmt.Println("You are an admin")
    }
}
```
*Reviewer thinks: "Okay, the admin check is commented out, or it's just a comment explaining the line. Wait, the brace is there. It looks like standard logic."*

**Logical View (What the compiler sees):**
```go
package main

func main() {
    accessLevel := "user"
    if accessLevel != "user" { // \u202E ⁦// Check if admin⁩ ⁦
        fmt.Println("You are an admin")
    }
}
```
*Wait, the RLO character (`\u202E`) flips the text direction.*

**Actual Execution Logic:**
The compiler sees the opening brace `{` as part of the comment because the Bidi characters rearranged the line structure in a way that the comment marker `//` consumed the logic that *looked* like it was before the comment.

*(Note: The exact mechanics depend on where the RLO is placed. A simpler example is hiding a return statement.)*

### Simpler Example: Hiding a Return
**Visual:**
```python
def check_password(password):
    if password == "secret":
        return True
    return False
    # return True ‮ ⁦ if password == "backdoor" ⁩ ⁦
```
**Logical:**
The Bidi characters can make code that is *active* look like it is *commented out*, or vice versa.

### Impact
- **Supply Chain Attacks**: Malicious code is committed to open source projects.
- **Code Review Bypass**: Reviewers approve code that looks safe but executes malicious logic.
- **Backdoors**: Hidden logic bombs in authentication or payment modules.

## Impact
- **Supply Chain Attacks**: Malicious code is committed to open source projects.
- **Code Review Bypass**: Reviewers approve code that looks safe but executes malicious logic.
- **Backdoors**: Hidden logic bombs in authentication or payment modules.

## Mitigation
- **Editor Warnings**: Modern editors (VS Code, GitHub UI) now highlight Bidi control characters with a warning "This document contains bidirectional characters".
- **Compiler Errors**: Newer compilers (GCC, Rust, Go) reject source files containing unclosed or suspicious Bidi characters.
- **Linters**: Use tools to scan for and ban Bidi characters (`\u202E`, `\u2066`, etc.) in source code files.
