_BASE64_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
def hex_to_base64(hex_str):
    if len(hex_str) % 2 != 0:
        print("invalid string length, must be divisible by two")
        return

    base64_str = ""

    for i in range(0, len(hex_str), 6):
        substr = hex_str[i:i+6]
        mask = 0xfc0000 
        shift = 3

        num_pad_bytes = 0
        if (len(substr) < 6):
            num_pad_bytes = 3 - len(substr) // 2

        substr_int_value = int(substr, 16)
        substr_int_value <<= (8 * num_pad_bytes)

        for i in range(shift, num_pad_bytes-1, -1):
            cur_value = (substr_int_value & mask) >> (shift * 6)
            base64_str += _BASE64_TABLE[cur_value]
            mask >>= 6
            shift -= 1

        base64_str += '=' * num_pad_bytes

    return base64_str
