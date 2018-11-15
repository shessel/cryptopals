import unittest
from cryptopals import set01
from Crypto.Cipher import AES
from Crypto import Random

class Base64Tests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(set01.bytes_to_base64(b''), '')

    def test_foobar(self):
        input_str = b'foobar'
        expected_outputs = ['Zg==', 'Zm8=', 'Zm9v', 'Zm9vYg==', 'Zm9vYmE=', 'Zm9vYmFy']
        for i in range(len(input_str)):
            with self.subTest(i=i):
                input_substr = input_str[0:i+1]
                base64_str = set01.bytes_to_base64(input_substr)
                self.assertEqual(base64_str, expected_outputs[i])

    def test_cryptopals(self):
        input = bytes.fromhex('49276d206b696c6c696e6720796f7572'
                              '20627261696e206c696b65206120706f'
                              '69736f6e6f7573206d757368726f6f6d')
        expected_output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        self.assertEqual(set01.bytes_to_base64(input), expected_output)

class Base64DecodeTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(set01.base64_to_bytes(b''), b'')

    def test_foobar(self):
        input_strs = [b'Zg==', b'Zm8=', b'Zm9v', b'Zm9vYg==', b'Zm9vYmE=', b'Zm9vYmFy']
        expected_output = b'foobar'
        for i in range(len(input_strs)):
            with self.subTest(i=i):
                output_substr = expected_output[0:i+1]
                base64_str = set01.base64_to_bytes(input_strs[i])
                self.assertEqual(base64_str, output_substr)

    def test_cryptopals(self):
        input = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        expected_output = bytes.fromhex('49276d206b696c6c696e6720796f7572'
                                        '20627261696e206c696b65206120706f'
                                        '69736f6e6f7573206d757368726f6f6d')
        self.assertEqual(set01.base64_to_bytes(input), expected_output)

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

class RepeatingKeyXorTests(unittest.TestCase):
    def test_cryptopals(self):
        input = (b"Burning 'em, if you ain't quick and nimble\n"
                 b"I go crazy when I hear a cymbal")
        output = bytes.fromhex('0b3637272a2b2e63622c2e69692a2369'
                               '3a2a3c6324202d623d63343c2a262263'
                               '24272765272a282b2f20430a652e2c65'
                               '2a3124333a653e2b2027630c692b2028'
                               '3165286326302e27282f')
        self.assertEqual(set01.repeating_key_xor(input, b'ICE'), output)

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
    def test_foobar(self):
        input_bytes = b'foobar foobar foobar foobar'
        xored_bytes = set01.fixed_xor(input_bytes, bytes([123] * len(input_bytes)))
        best_text, xor_byte, _score = set01.break_single_byte_xor(xored_bytes)
        self.assertEqual(best_text, b'foobar foobar foobar foobar')
        self.assertEqual(xor_byte, 123)

    def test_cryptopals(self):
        input_bytes = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
        best_text, _xor_byte, _score = set01.break_single_byte_xor(input_bytes)
        self.assertEqual(best_text, b"Cooking MC's like a pound of bacon")

class FindSingleByteXorTests(unittest.TestCase):
    def test_foobar(self):
        input_bytes = b'foobar foobar foobar foobar'
        xored_bytes = set01.fixed_xor(input_bytes, bytes([123] * len(input_bytes)))
        # rest is random hex bytes
        candidate_inputs = [
            bytes.fromhex('977dd32697ea9c91a11dbcac7c14443d442b21a59139e7447625b0'),
            bytes.fromhex('e78ec6dfb1c088c07ca4b739a2b584eebce4965c998508b304123b'),
            bytes.fromhex('bc8f6af1121680540926442b3a0947daaed972fe7e82c97e186bcf'),
            bytes.fromhex('82bec6bddc69afd5171426e6c11b558438b0e3a0eed060f3c6baf2'),
            xored_bytes,
            bytes.fromhex('9c9735c58952e04944307fa70e4b341719a8c4e5ac0aeb17b6ca25'),
            bytes.fromhex('6c4829e24230a1d1353f896bda57fab4ba20ff9ff5520d75f4d465'),
            bytes.fromhex('e81dd9e29471f5d1f3f78f8b589dc51ecf33bb5cf27118aec42f97'),
            bytes.fromhex('3019db123fa1281f4027720e9b4be526cb5902f2da5a6ce3d1df48'),
            bytes.fromhex('a7e458b2b0d831a0fd83b7ccdc30750586b2418a2a534be93f7fd4'),
            bytes.fromhex('b659b90920cb29f962532ae31edbe2bccd6d470f38b65017852eae'),
            bytes.fromhex('58452865ba441420ea043b6886123bd9f2c946fb058609e72b47b9'),
        ]
        best_text, best_i = set01.find_single_byte_xor(candidate_inputs)
        self.assertEqual(best_text, b'foobar foobar foobar foobar')
        self.assertEqual(best_i, 4)

    @unittest.skip("takes a while and is only for challenge")
    def test_cryptopals(self):
        with open('input/detect-single-byte-xor.txt') as file:
            candidate_inputs = [
                bytes.fromhex(line.strip()) for line in file 
            ]
        best_text, best_i = set01.find_single_byte_xor(candidate_inputs)
        self.assertEqual(best_text, b'Now that the party is jumping\n')
        self.assertEqual(best_i, 170)

class EditDistanceTests(unittest.TestCase):
    def test_same(self):
        self.assertEqual(set01.edit_distance(b'foobar', b'foobar'), 0)

    def test_against_all_bits_set(self):
        for i in range(32):
            with self.subTest(i=i):
                self.assertEqual(set01.edit_distance(bytes.fromhex('ffffffff'), (0xffffffff >> i).to_bytes(4, byteorder='big')), i)

    def test_alternating_patterns(self):
        with self.subTest(i=0):
            self.assertEqual(set01.edit_distance(bytes([0x55]), bytes([0xaa])), 8)
        with self.subTest(i=1):
            self.assertEqual(set01.edit_distance(bytes([0x33]), bytes([0xcc])), 8)
        with self.subTest(i=2):
            self.assertEqual(set01.edit_distance(bytes([0x0f]), bytes([0xf0])), 8)

    def test_cryptopals(self):
        self.assertEqual(set01.edit_distance(b'this is a test', b'wokka wokka!!!'), 37)

class BreakRepeatingKeyXorTests(unittest.TestCase):
    def test_foobar(self):
        input = b' '.join([b'Foo Ba Rfo, obarf Oob arfo. Oba rfoo? Barf OOBA R.F., oobar!']*4)
        key = b'foobar!'
        input_enc = set01.repeating_key_xor(input, key)
        self.assertEqual(set01.break_repeating_key_xor(input_enc), key)

    def test_cryptopals(self):
        input_base64 = set01.read_base64_from_file('input/repeating-key-xor.txt')
        input_bytes = set01.base64_to_bytes(input_base64)
        key = b'Terminator X: Bring the noise'
        self.assertEqual(set01.break_repeating_key_xor(input_bytes), key)

class DecryptAesEcbTests(unittest.TestCase):
    def test_foobar(self):
        text = b'foobarfoobarfoob'
        key = b'foobarfoobarfoob'
        input = AES.new(key, AES.MODE_ECB).encrypt(text)
        self.assertEqual(set01.decrypt_aes_ecb(key, input), text)

    def test_cryptopals(self):
        key = b'YELLOW SUBMARINE'
        base64_input = set01.read_base64_from_file('input/aes-ecb.txt')
        input = bytes(set01.base64_to_bytes(base64_input))
        output = set01.decrypt_aes_ecb(key, input)
        with open('output/aes-ecb.txt', 'rb') as file:
            expected_output = file.read()
            self.assertEqual(output, expected_output)

class FindDuplicateBlocksTests(unittest.TestCase):
    def test_first_block_equals_last_block(self):
        input = bytearray([i for i in range(256)])
        input[240:256] = input[0:16]
        self.assertEqual(set01.find_duplicate_blocks(input), (0, 240))

    def test_success(self):
        input = bytes([i%16 for i in range(256)])
        self.assertEqual(set01.find_duplicate_blocks(input), (0, 16))

    def test_failure(self):
        input = bytes([i for i in range(256)])
        for test_i in [2**i for i in range(8)]:
            with self.subTest(i=test_i):
                self.assertEqual(set01.find_duplicate_blocks(input, test_i), None)

    def test_assert_block_size(self):
        input = bytes([i for i in range(13)])
        for test_i in range(12):
            with self.subTest(i=test_i):
                self.assertRaises(AssertionError)

class DetectAesEcbTests(unittest.TestCase):
    def test_cryptopals(self):
        with open('input/detect-aes-ecb.txt') as file:
            inputs = [bytes.fromhex(line.strip()) for line in file]
        self.assertEqual(set01.detect_aes_ecb(inputs), [132])

    def test_random_data(self):
        gen = Random.new()
        expected_indices = [2, 13, 42]
        inputs = []
        for i in range(63):
            if i in expected_indices:
                text = bytearray(gen.read(256))
                text[240:256] = text[0:16]
                key = gen.read(16)
                inputs.append(AES.new(key, AES.MODE_ECB).encrypt(bytes(text)))
            else:
                inputs.append(gen.read(256))

        self.assertEqual(set01.detect_aes_ecb(inputs), expected_indices)
