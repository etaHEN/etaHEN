import argparse

def xor_encrypt(data, key):
    key_bytes = key.encode()  # Convert key string to bytes
    encrypted_data = bytearray()
    key_len = len(key_bytes)

    for i, byte in enumerate(data):
        encrypted_data.append(byte ^ key_bytes[i % key_len])
    
    return encrypted_data

def xor_decrypt(data, key):
    return xor_encrypt(data, key)  # XOR decryption is symmetric

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a string using XOR encryption with a Base64 key.")
    parser.add_argument('input_string', type=str, help='The string to be encrypted')

    args = parser.parse_args()

    input_string = args.input_string
    
    # Use the Base64 string directly as the key
    key = 'U0lTVFIwX0lfU0VFX1lPVQ==';
    
    # Convert input string to bytes
    data = input_string.encode()
    
    # Encrypt the data
    encrypted_data = xor_encrypt(data, key)
    
    # To save to a file (optional)
    with open('encrypted_output.bin', 'wb') as f:
        f.write(encrypted_data)
    
    encrypted_c_string = ''.join(f'\\x{byte:02x}' for byte in encrypted_data)
    c_string_output = f'const char* enc_ver = "{encrypted_c_string}";'
    print(c_string_output)
    
    
    # Decrypt the data
    decrypted_data = xor_decrypt(encrypted_data, key)
    decrypted_string = decrypted_data.decode()
    
    print(f"Decrypted string: {decrypted_string}")