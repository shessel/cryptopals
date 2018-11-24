from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES
from cryptopals import set01

def pkcs7_padding(input, block_size=16):
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

def aes_encryption_oracle(input_bytes):
    random_gen = Random.new()
    random_key = random_gen.read(16)
    num_pad_bytes_front = random.randint(5,10)
    num_pad_bytes_back = random.randint(5,10)
    padded_input = pkcs7_padding(
        random_gen.read(num_pad_bytes_front) +
        input_bytes +
        random_gen.read(num_pad_bytes_back)
    )
    if random.randint(0, 1) == 0:
        return encrypt_aes_ecb(random_key, padded_input), 'ecb'
    else:
        random_iv = random_gen.read(16)
        return encrypt_aes_cbc(random_key, padded_input, random_iv), 'cbc'

def detect_ecb_or_cbc(input_bytes):
    is_ecb = len(set01.detect_aes_ecb([input_bytes])) > 0
    if is_ecb:
        return 'ecb'
    else:
        return 'cbc'
