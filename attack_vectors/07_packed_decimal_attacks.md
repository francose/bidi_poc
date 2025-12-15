# Packed Decimal (BCD) Attacks

## Mechanism
Packed Decimal (Binary Coded Decimal) is used primarily in mainframes (IBM z/OS) and financial systems (COBOL) to store numbers with exact precision. Attacks exploit the lack of strict validation in the nibble structure.

## The Vulnerability
- **Structure**: Each byte contains two digits (nibbles). The last nibble is the sign.
- **Sign Nibbles**:
    - `0xC` (1100): Positive (+)
    - `0xD` (1101): Negative (-)
    - `0xF` (1111): Unsigned (usually treated as positive)
- **Digit Nibbles**: Must be `0x0` to `0x9`.

## Real-Life Example: Financial Transaction Tampering

### The Scenario
A legacy banking system uses the ISO 8583 standard (common for credit card transactions) or a proprietary mainframe protocol that transmits amounts in Packed Decimal format to save bandwidth.

### The Data
- **Field**: Transaction Amount
- **Value**: $100.00
- **Format**: Packed Decimal (2 digits per byte)
- **Hex Representation**: `0x10 0x00 0x0C`
    - `10` = Digits 1, 0
    - `00` = Digits 0, 0
    - `0C` = Digit 0, Sign C (+)

### The Attack
An attacker performs a Man-in-the-Middle (MitM) attack on the transaction stream.

1.  **Intercept**: `0x10 0x00 0x0C` ($100.00 Credit)
2.  **Modify**: The attacker flips the first nibble from `1` to `9`.
    - New Hex: `0x90 0x00 0x0C`
3.  **Result**: The system processes a transaction for **$900.00**.

### Variant: The Refund Scam (Sign Flipping)
1.  **Intercept**: A debit (payment) of $1000.
    - `0x10 0x00 0x0D` (D = Minus/Debit)
2.  **Modify**: Change `D` to `C`.
    - `0x10 0x00 0x0C` (C = Plus/Credit)
3.  **Result**: Instead of paying $1000, the attacker receives a $1000 refund.

## Impact
- **Financial Fraud**: Altering transaction values or signs.
- **Denial of Service**: Crashing legacy applications that panic on invalid BCD.
- **Logic Errors**: Corrupting database records.

## Mitigation
- **Strict Validation**: Validate every nibble before processing. Ensure digits are 0-9 and signs are valid (C, D, F).
- **Checksums**: Use cryptographic signatures (MACs) on transaction data to detect tampering.
- **Modernization**: Where possible, migrate to standard integer types with overflow protection, though this is difficult in legacy environments.
