# xor_encrypt.py

def xor_encrypt(input_file, output_file, key):
    key_bytes = key.encode()  # Convert key string to bytes
    with open(input_file, 'rb') as f:
        data = f.read()
    
    encrypted_data = bytearray()
    key_len = len(key_bytes)

    for i, byte in enumerate(data):
        encrypted_data.append(byte ^ key_bytes[i % key_len])
    
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

if __name__ == '__main__':
    key_base64 = 'U0lTVFIwX0lfU0VFX1lPVQ=='  # Base64 encoded key string
    
    # Use the Base64 string directly as the key
    xor_encrypt('shellui/assets/etaHEN_toolbox.xml', 'shellui/assets/etaHEN_toolbox.sxml', key_base64)
    xor_encrypt('shellui/assets/etaHEN_Lite.xml', 'shellui/assets/etaHEN_Lite.sxml', key_base64)
