import operator
import collections
import functools
from Crypto.Cipher import AES

def bytes_to_base64(bytes):
    BASE64_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    base64_str = ""

    for i in range(0, len(bytes), 3):
        substr = bytes[i:i+3]
        mask = 0xfc0000 
        shift = 3

        num_pad_bytes = 0
        if (len(substr) < 3):
            num_pad_bytes = 3 - len(substr)

        substr_int_value = int.from_bytes(substr, byteorder='big')
        substr_int_value <<= (8 * num_pad_bytes)

        for i in range(shift, num_pad_bytes-1, -1):
            cur_value = (substr_int_value & mask) >> (shift * 6)
            base64_str += BASE64_TABLE[cur_value]
            mask >>= 6
            shift -= 1

        base64_str += '=' * num_pad_bytes

    return base64_str

def base64_to_bytes(base64_bytes):
    BASE64_TABLE = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    bytes = bytearray()
    for i in range(0, len(base64_bytes), 4):
        substr = base64_bytes[i:i+4]
        is_last_group = len(base64_bytes) - i <= 4
        num_pad_bytes = 0
        if is_last_group:
            substr = substr.rstrip(b'=')
            num_pad_bytes = 4 - len(substr)
        group_value = functools.reduce(lambda x, y: (x << 6) + BASE64_TABLE.index(y), substr, 0)
        # number of = in substr equals number of pad bytes so len(substr) - 1 is always the
        if is_last_group:
            group_value <<= (6 * num_pad_bytes)
        # number of actual data carrying bytes
        for j in range(2, num_pad_bytes -1, -1):
            mask = 0xff << (8 * j)
            bytes.append((group_value & mask) >> (8 * j))
    return bytes

def fixed_xor(bytes1, bytes2):
    if len(bytes1) != len(bytes2):
        print("strings have unequal length")
        return bytearray()

    return bytearray(map(operator.xor, bytes1, bytes2))

def repeating_key_xor(bytes1, key):
    return bytes([char ^ key[i % len(key)] for (i, char) in enumerate(bytes1)])

def score_text(text_bytes):
    # from http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
    # mixed with https://mdickens.me/typing/letter_frequency.html
    # as the latter is missing numbers, just use the next characters frequency from the table
    # and give a small score to remaining ones. Except for Space which seemed to justify a higher score
    SCORE_BY_CHAR = {
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
    scorable_bytes = filter(lambda char: char in SCORE_BY_CHAR.keys(), text_bytes.upper())
    byte_counts = collections.Counter(scorable_bytes)
    score_byte = lambda byte_count_item: SCORE_BY_CHAR[byte_count_item[0]] * byte_count_item[1]
    score = functools.reduce(operator.add, map(score_byte, byte_counts.items()), 0.0)
    
    return score

def break_single_byte_xor(xored_bytes):
    best_text = ""
    best_xor_byte = 0
    best_score = 0.0
    for xor_byte in range(256):
        text_candidate = fixed_xor(xored_bytes, bytes([xor_byte]*len(xored_bytes)))
        candidate_score = score_text(text_candidate) 
        if candidate_score > best_score:
            best_text = text_candidate
            best_xor_byte = xor_byte
            best_score = candidate_score
    return best_text, best_xor_byte, best_score

def find_single_byte_xor(candidate_inputs):
    best_score = 0.0
    best_text = ""
    best_i = 0
    for i, candidate_input in enumerate(candidate_inputs):
        candidate_text, _xor_byte, candidate_score = break_single_byte_xor(candidate_input)
        if candidate_score > best_score:
            best_score = candidate_score
            best_text = candidate_text
            best_i = i
    return best_text, best_i

def edit_distance(bytes1, bytes2):
    distance = 0
    for xored_byte in fixed_xor(bytes1, bytes2):
        num_bits = 0
        while xored_byte > 0:
            xored_byte &= xored_byte-1
            num_bits += 1
        distance += num_bits
    return distance

def score_xor_key_size(bytes, num_blocks_to_test=2, min_key_size=2, max_key_size=40):
    key_scores = dict()
    for key_size in range(min_key_size, max_key_size+1):
        key_score = 0.0
        max_blocks = len(bytes) // key_size
        if max_blocks < 2:
            break
        num_distances_to_consider = min(max_blocks, num_blocks_to_test)-1
        for block_i in range(num_distances_to_consider):
            first_block = bytes[block_i*key_size:(block_i+1)*key_size]
            second_block = bytes[(block_i+1)*key_size:(block_i+2)*key_size]
            key_score += edit_distance(first_block, second_block)
        key_scores[key_size] = key_score / (key_size * num_distances_to_consider)
    return key_scores

def read_base64_from_file(filename):
    with open(filename, 'rb') as file:
        return b''.join([line.strip() for line in file])

def break_repeating_key_xor(bytes, max_key_sizes=1):
    key_scores = score_xor_key_size(bytes, 10)
    sorted_key_scores = sorted(key_scores.items(), key=lambda key_value: (key_value[1], key_value[0]))
    for i in range(max_key_sizes):
        key_size = sorted_key_scores[i][0]
        key = bytearray()
        for n in range(key_size):
            nth_bytes = bytes[n::key_size]
            _best_text, xor_byte, _best_score = break_single_byte_xor(nth_bytes)
            key.append(xor_byte)
    return key

def decrypt_aes_ecb(key, text):
    return AES.new(key, AES.MODE_ECB).decrypt(text)

def find_duplicate_blocks(bytes, block_size=16):
    assert (len(bytes) % block_size) == 0
    for block_start in range(0, len(bytes) - block_size, block_size):
        block = bytes[block_start:block_start+block_size]
        for compare_start in range(block_start+block_size, len(bytes), block_size):
            if block == bytes[compare_start:compare_start+block_size]:
                return(block_start, compare_start)

def detect_aes_ecb(candidates):
    possible_aes_ecb = []
    for i, candidate in enumerate(candidates):
        if find_duplicate_blocks(candidate):
            possible_aes_ecb.append(i)
    return possible_aes_ecb
