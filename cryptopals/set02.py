from Crypto.Cipher import AES
from cryptopals import set01

def pkcs7_padding(input, block_size):
    num_blocks = len(input) // block_size
    last_block_size = len(input) - num_blocks * block_size
    num_pad_bytes = block_size - last_block_size
    return input + bytes([num_pad_bytes] * num_pad_bytes)

def encrypt_aes_ecb(key, text):
    return AES.new(key, AES.MODE_ECB).encrypt(text)

def encrypt_aes_cbc(key, text, iv = bytes([0] * 16)):
    assert len(key) == 16
    assert len(iv) == 16
    xor_block = iv
    encrypted_text = b''
    for block_start in range(0, len(text), 16):
        xored_block = bytes([text[block_start + i] ^ xor_block[i] for i in range(16)])
        encrypted_block = encrypt_aes_ecb(key, xored_block)
        encrypted_text += encrypted_block
        xor_block = encrypted_block
    return encrypted_text

def decrypt_aes_cbc(key, encrypted_text, iv = bytes([0] * 16)):
    assert len(key) == 16
    assert len(iv) == 16
    xor_block = iv
    decrypted_text = b''
    for block_start in range(0, len(encrypted_text), 16):
        encrypted_block = encrypted_text[block_start:block_start+16]
        decrypted_block = set01.decrypt_aes_ecb(key, bytes(encrypted_block))
        xored_block = bytes([decrypted_block[i] ^ xor_block[i] for i in range(16)])
        decrypted_text += xored_block
        xor_block = encrypted_block
    return decrypted_text
