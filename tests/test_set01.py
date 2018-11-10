import unittest
from cryptopals import set01

class Base64Tests(unittest.TestCase):
    @staticmethod
    def _ascii_to_hex(string):
        return ''.join([format(ord(c), "x") for c in string])

    def test_empty(self):
        self.assertEqual(set01.hex_to_base64(""), "")

    def test_uneven_length(self):
        self.assertEqual(set01.hex_to_base64("a"), None)

    def test_foobar(self):
        input_str = "foobar"
        expected_outputs = ["Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"]
        for i in range(len(input_str)):
            with self.subTest(i=i):
                input_substr = input_str[0:i+1]
                hex_str = self._ascii_to_hex(input_substr)
                base64_str = set01.hex_to_base64(hex_str)
                self.assertEqual(base64_str, expected_outputs[i])

    def test_cryptopals_example(self):
        self.assertEqual(set01.hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
