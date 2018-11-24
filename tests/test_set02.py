import unittest
from cryptopals import set01
from cryptopals import set02

class Pkcs7PaddingTests(unittest.TestCase):
    def test_pad_to_16_bytes(self):
        self.assertEqual(set02.pkcs7_padding(b'foobar', 16), b'foobar' + bytes([10] * 10))

    def test_pad_to_32_bytes(self):
        self.assertEqual(set02.pkcs7_padding(b'foobar', 32), b'foobar' + bytes([26] * 26))

    def test_cryptopals(self):
        self.assertEqual(set02.pkcs7_padding(b'YELLOW SUBMARINE', 20), b'YELLOW SUBMARINE\x04\x04\x04\x04')

class AesCbcEncryptTests(unittest.TestCase):
    def test_single_block_zero_iv(self):
        input = b'abcdefghijklmnop'
        key = b'foobarfoobarfoob'
        expected_output = set02.encrypt_aes_ecb(key, input)
        self.assertEqual(set02.encrypt_aes_cbc(key, input), expected_output)

    def test_cryptopals(self):
        with open('output/decrypt-aes-cbc.txt', 'rb') as output_file:
            output_bytes = output_file.read()
        input_base64 = set01.read_base64_from_file('input/decrypt-aes-cbc.txt')
        input_bytes = set01.base64_to_bytes(input_base64)
        self.assertEqual(set02.encrypt_aes_cbc(b'YELLOW SUBMARINE', output_bytes), input_bytes)

class AesCbcDecryptTests(unittest.TestCase):
    def test_single_block_zero_iv(self):
        input = b'abcdefghijklmnop'
        key = b'foobarfoobarfoob'
        encrypted_input = set02.encrypt_aes_cbc(key, input)
        self.assertEqual(set02.decrypt_aes_cbc(key, encrypted_input), input)

    def test_single_block(self):
        input = b'abcdefghijklmnop'
        key = b'foobarfoobarfoob'
        iv = b'narfnarfnarfnarf'
        encrypted_input = set02.encrypt_aes_cbc(key, input, iv)
        self.assertEqual(set02.decrypt_aes_cbc(key, encrypted_input, iv), input)

    def test_multi_block_zero_iv(self):
        input = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+'
        key = b'foobarfoobarfoob'
        encrypted_input = set02.encrypt_aes_cbc(key, input)
        self.assertEqual(set02.decrypt_aes_cbc(key, encrypted_input), input)

    def test_multi_block(self):
        input = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+'
        key = b'foobarfoobarfoob'
        iv = b'narfnarfnarfnarf'
        encrypted_input = set02.encrypt_aes_cbc(key, input, iv)
        self.assertEqual(set02.decrypt_aes_cbc(key, encrypted_input, iv), input)

    def test_cryptopals(self):
        input_base64 = set01.read_base64_from_file('input/decrypt-aes-cbc.txt')
        input_bytes = set01.base64_to_bytes(input_base64)
        with open('output/decrypt-aes-cbc.txt', 'rb') as output_file:
            output_bytes = output_file.read()
        self.assertEqual(set02.decrypt_aes_cbc(b'YELLOW SUBMARINE', input_bytes), output_bytes)

class AesDetectionOracleTests(unittest.TestCase):
    def test_aes_encryption_oracle(self):
        for i in range(32):
            oracle_bytes, mode = set02.aes_encryption_oracle(b'f' * 48)
            self.assertEqual(set02.detect_ecb_or_cbc(oracle_bytes), mode)
