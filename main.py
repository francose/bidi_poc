
def write_into_file(filename, content, encoding):
    """Write the byte representation into a file for comparison."""
    with open(filename, 'w') as file:
        file.write(f"Encoding: {encoding}\n")
        file.write(f"Total bytes: {len(content)}\n")
        file.write("-" * 50 + "\n")
        file.write("Index | Decimal | Hex    | Binary\n")
        file.write("-" * 50 + "\n")
        for i, byte in enumerate(content):
            file.write(f"{i:5} | {byte:7} | 0x{byte:02x}   | {bin(byte)}\n")
        file.write("-" * 50 + "\n")
        file.write(f"Hex dump: {content.hex()}\n")


def encode_packed_decimal(text):
    """
    Encode each character's ASCII value as Packed Decimal (BCD).
    Each decimal digit becomes a 4-bit nibble.
    Two nibbles are packed into one byte.
    The last nibble is a sign (0xC = positive, 0xD = negative, 0xF = unsigned).
    """
    packed_bytes = []
    
    for char in text:
        ascii_val = ord(char)
        # Convert ASCII value to string of digits
        digits = str(ascii_val)
        
        nibbles = [int(d) for d in digits]
        # Add sign nibble (0xF for unsigned)
        nibbles.append(0xF)
        
        # Pad to even number of nibbles
        if len(nibbles) % 2 != 0:
            nibbles.insert(0, 0)
        
        # Pack nibbles into bytes (2 nibbles per byte)
        for i in range(0, len(nibbles), 2):
            byte = (nibbles[i] << 4) | nibbles[i + 1]
            packed_bytes.append(byte)
    
    return bytes(packed_bytes)


def write_packed_decimal_file(filename, text):
    """Write packed decimal representation to file."""
    with open(filename, 'w') as file:
        file.write("Encoding: Packed Decimal (BCD)\n")
        file.write("-" * 60 + "\n")
        file.write("Char | ASCII | Digits | Packed Bytes (hex)\n")
        file.write("-" * 60 + "\n")
        
        all_packed = []
        for char in text:
            ascii_val = ord(char)
            digits = str(ascii_val)
            
            nibbles = [int(d) for d in digits]
            nibbles.append(0xF)  # Sign nibble
            
            if len(nibbles) % 2 != 0:
                nibbles.insert(0, 0)
            
            packed = []
            for i in range(0, len(nibbles), 2):
                byte = (nibbles[i] << 4) | nibbles[i + 1]
                packed.append(byte)
                all_packed.append(byte)
            
            packed_hex = ' '.join(f'0x{b:02x}' for b in packed)
            file.write(f"  {char}  |  {ascii_val:3}  | {digits:>5}  | {packed_hex}\n")
        
        file.write("-" * 60 + "\n")
        file.write(f"Total bytes: {len(all_packed)}\n")
        file.write(f"Hex dump: {bytes(all_packed).hex()}\n")
        
        # Explain the format
        file.write("\n" + "=" * 60 + "\n")
        file.write("Format explanation:\n")
        file.write("- Each ASCII value is converted to decimal digits\n")
        file.write("- Each digit is stored in 4 bits (nibble)\n")
        file.write("- Two nibbles packed per byte\n")
        file.write("- 0xF = unsigned sign nibble at end\n")
        file.write("- Example: 'h'=104 -> digits '104' -> nibbles [0,1,0,4,F]\n")
        file.write("          -> packed as 0x01, 0x04f (bytes: 0x01 0x4f)\n")
    
    return encode_packed_decimal(text)


def show_memory_addresses(text):
    """Display memory address of a string and each character."""
    
    # Get memory address of the entire string
    print(f"String: '{text}'")
    print(f"String memory address: {hex(id(text))}")
    print("-" * 50)
    
    # Show each character and its memory address
    print("Character | Index | Memory Address (hex)")
    print("-" * 50)
    
    for index, char in enumerate(text):
        # Each character is a new string object in Python
        char_address = id(char)
        print(f"   '{char}'     |   {index}   | {hex(char_address)}")
    
    print("-" * 50)
    
    # Show raw bytes and their positions
    print("\nRaw bytes representation:")
    encoded = text.encode('utf-8')
    for i, byte in enumerate(encoded):
        print(f"Byte {i}: {byte} (0x{byte:02x}) = '{chr(byte)}'")
       
    write_into_file("output_utf8.txt", encoded, "utf-8")


    encoded_utf16 = text.encode('utf-16')
    print("\nUTF-16 bytes representation:")    
    for i, byte in enumerate(encoded_utf16):
        print(f"Byte {i}: {byte} (0x{byte:02x}) = '{chr(byte)}'")
        
    write_into_file("output_utf16.txt", encoded_utf16, "utf-16")

    encoded_utf32 = text.encode('utf-32')
    print("\nUTF-32 bytes representation:")    
    for i, byte in enumerate(encoded_utf32):
        print(f"Byte {i}: {byte} (0x{byte:02x}) = '{chr(byte)}'")

    write_into_file("output_utf32.txt", encoded_utf32, "utf-32")

    # Packed Decimal (BCD) encoding
    print("\nPacked Decimal (BCD) bytes representation:")
    packed = encode_packed_decimal(text)
    for i, byte in enumerate(packed):
        high_nibble = (byte >> 4) & 0x0F
        low_nibble = byte & 0x0F
        low_str = 'F(sign)' if low_nibble == 0xF else str(low_nibble)
        print(f"Byte {i}: {byte:3} (0x{byte:02x}) = nibbles [{high_nibble}, {low_str}]")
    
    write_packed_decimal_file("output_packed_decimal.txt", text)

# Example usage
if __name__ == "__main__":
    word = "hello"
    show_memory_addresses(word)
    

