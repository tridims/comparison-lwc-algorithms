def to_hex(byte_str: bytes, sep=" ", bytes_per_sep=2):
    """Converts bytes to a hex string, with segment division from left"""
    hexstr = byte_str.hex()
    if bytes_per_sep < 1:
        bytes_per_sep = len(hexstr)
    chunks = [
        hexstr[i : i + (bytes_per_sep << 1)]
        for i in range(0, len(hexstr), bytes_per_sep << 1)
    ]
    return sep.join(chunks)
