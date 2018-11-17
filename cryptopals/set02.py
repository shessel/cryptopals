def pkcs7_padding(input, block_size):
    num_blocks = len(input) // block_size
    last_block_size = len(input) - num_blocks * block_size
    num_pad_bytes = block_size - last_block_size
    return input + bytes([num_pad_bytes] * num_pad_bytes)
