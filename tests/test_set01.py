import unittest
from cryptopals import set01

class Base64Tests(unittest.TestCase):
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

class TextScoringTests(unittest.TestCase):
    _SCORE_BY_CHAR = {
        ord(' '): 18.00,
        ord('E'): 12.02,
        ord('T'):  9.10,
        ord('A'):  8.12,
        ord('O'):  7.68,
        ord('I'):  7.31,
        ord('N'):  6.95,
        ord('S'):  6.28,
        ord('R'):  6.02,
        ord('H'):  5.92,
        ord('D'):  4.32,
        ord('L'):  3.98,
        ord('U'):  2.88,
        ord('C'):  2.71,
        ord('M'):  2.61,
        ord('F'):  2.30,
        ord('Y'):  2.11,
        ord('W'):  2.09,
        ord('G'):  2.03,
        ord('P'):  1.82,
        ord('B'):  1.49,
        ord(','):  1.11,
        ord('.'):  1.11,
        ord('V'):  1.11,
        ord('K'):  0.69,
        ord('-'):  0.17,
        ord('_'):  0.17,
        ord('"'):  0.17,
        ord("'"):  0.17,
        ord('X'):  0.17,
        ord('('):  0.11,
        ord(')'):  0.11,
        ord(';'):  0.11,
        ord('0'):  0.11,
        ord('1'):  0.11,
        ord('Q'):  0.11,
        ord('2'):  0.10,
        ord(':'):  0.10,
        ord('J'):  0.10,
        ord('Z'):  0.07,
        ord('/'):  0.03,
        ord('*'):  0.03,
        ord('!'):  0.03,
        ord('?'):  0.03,
        ord('$'):  0.03,
        ord('3'):  0.03,
        ord('5'):  0.03,
        ord('>'):  0.03,
        ord('{'):  0.03,
        ord('}'):  0.03,
        ord('4'):  0.03,
        ord('9'):  0.03,
        ord('['):  0.03,
        ord(']'):  0.03,
        ord('8'):  0.03,
        ord('6'):  0.03,
        ord('7'):  0.03,
        ord('\\'): 0.03,
        ord('+'):  0.03,
        ord('|'):  0.03,
        ord('&'):  0.03,
        ord('<'):  0.03,
        ord('%'):  0.03,
        ord('@'):  0.03,
        ord('#'):  0.03,
        ord('^'):  0.03,
        ord('`'):  0.03,
        ord('~'):  0.03,
    }

    def test_score_empty(self):
        self.assertEqual(set01.score_text(b''), 0.0)

    def test_score_non_printable_lower(self):
        self.assertEqual(set01.score_text(bytes([i for i in range(32)])), 0.0)

    def test_score_non_printable_upper(self):
        self.assertEqual(set01.score_text(bytes([i for i in range(127,256)])), 0.0)

    def test_score_every_char(self):
        self.assertEqual(set01.score_text(b' ETAOINSRHDLUCMFYWGPB,.VK-_"\'X();01Q2:JZ/*!?$35>{}49[]867\\+|&<%@#^`~'), sum(self._SCORE_BY_CHAR.values()))

    def test_score_foobar(self):
        self.assertAlmostEqual(set01.score_text(b'foobar'), sum([self._SCORE_BY_CHAR[c] for c in b'FOOBAR']))

class BreakSingleByteXorTests(unittest.TestCase):
    def test_cryptopals(self):
        self.assertEqual(set01.break_single_byte_xor(bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')), b"Cooking MC's like a pound of bacon")
