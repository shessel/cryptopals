import unittest
from cryptopals import set02

class Pkcs7PaddingTests(unittest.TestCase):
    def test_pad_to_16_bytes(self):
        self.assertEqual(set02.pkcs7_padding(b'foobar', 16), b'foobar' + bytes([10] * 10))

    def test_pad_to_32_bytes(self):
        self.assertEqual(set02.pkcs7_padding(b'foobar', 32), b'foobar' + bytes([26] * 26))

    def test_cryptopals(self):
        self.assertEqual(set02.pkcs7_padding(b'YELLOW SUBMARINE', 20), b'YELLOW SUBMARINE\x04\x04\x04\x04')
