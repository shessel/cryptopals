import unittest
from cryptopals import set01

class Base64Tests(unittest.TestCase):
    @staticmethod
    def _ascii_to_hex(string):
        return ''.join([format(ord(c), 'x') for c in string])

    def test_empty(self):
        self.assertEqual(set01.hex_to_base64(b''), '')

    def test_foobar(self):
        input_str = b'foobar'
        expected_outputs = ['Zg==', 'Zm8=', 'Zm9v', 'Zm9vYg==', 'Zm9vYmE=', 'Zm9vYmFy']
        for i in range(len(input_str)):
            with self.subTest(i=i):
                input_substr = input_str[0:i+1]
                base64_str = set01.hex_to_base64(input_substr)
                self.assertEqual(base64_str, expected_outputs[i])

    def test_cryptopals(self):
        input = bytes.fromhex('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
        expected_output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        self.assertEqual(set01.hex_to_base64(input), expected_output)

class FixedXorTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(set01.fixed_xor(b'',b''), b'')

    def test_first_longer(self):
        self.assertEqual(set01.fixed_xor(b'foobar',b'foo'), b'')

    def test_second_longer(self):
        self.assertEqual(set01.fixed_xor(b'foobar',b'foo'), b'')

    def test_xor_same(self):
        self.assertEqual(set01.fixed_xor(b'foobar',b'foobar'), b'\0\0\0\0\0\0')

    def test_xor_alternating(self):
        self.assertEqual(set01.fixed_xor(bytes.fromhex('5555'),bytes.fromhex('aaaa')), bytes.fromhex('ffff'))

    def test_cryptopals(self):
        input1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
        input2 = bytes.fromhex('686974207468652062756c6c277320657965')
        expected_output = bytes.fromhex('746865206b696420646f6e277420706c6179')
        self.assertEqual(set01.fixed_xor(input1, input2), expected_output)
