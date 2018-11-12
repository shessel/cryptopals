import operator
import collections
import functools

def hex_to_base64(hex_bytes):
    BASE64_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    base64_str = ""

    for i in range(0, len(hex_bytes), 3):
        substr = hex_bytes[i:i+3]
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
