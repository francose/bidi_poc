#!/usr/bin/env python3
"""Trojan Source sample — visible rendering lies about the byte content."""

access_level = "user‮ ⁦# Check if admin⁩ ⁦"

# A reviewer scanning this in GitHub or VS Code will SEE:
#     access_level = "user"  # Check if admin
#
# ... and reasonably conclude: "ok, normal user, harmless".

if access_level == "user":
    print("[GRANTED] regular user access (what the reviewer expects)")
else:
    print("[GRANTED] ADMIN access — silent privilege escalation")
