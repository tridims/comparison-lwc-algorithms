__author__ = "Iurii Sergiichuk"

""" PRESENT block cipher implementation

USAGE EXAMPLE:
---------------
Importing:
-----------
>>> from pypresent import Present

Encrypting with a 80-bit key:
------------------------------
>>> key = bytes.fromhex("00000000000000000000")
>>> plain = bytes.fromhex("0000000000000000")
>>> cipher = Present(key)
>>> encrypted = cipher.encrypt(plain)
>>> encrypted.hex()
'5579c1387b228445'
>>> decrypted = cipher.decrypt(encrypted)
>>> decrypted.hex()
'0000000000000000'

Encrypting with a 128-bit key:
-------------------------------
>>> key = bytes.fromhex("0123456789abcdef0123456789abcdef")
>>> plain = bytes.fromhex("0123456789abcdef")
>>> cipher = Present(key)
>>> encrypted = cipher.encrypt(plain)
>>> encrypted.hex()
'0e9d28685e671dd6'
>>> decrypted = cipher.decrypt(encrypted)
>>> decrypted.hex()
'0123456789abcdef'

fully based on standard specifications: http://www.crypto.ruhr-uni-bochum.de/imperia/md/content/texte/publications/conferences/present_ches2007.pdf
test vectors: http://www.crypto.ruhr-uni-bochum.de/imperia/md/content/texte/publications/conferences/slides/present_testvectors.zip
"""


from core import BlockCipher


class PresentCipher:
    def __init__(self, key, rounds=32):
        """Create a PRESENT cipher object

        key:    the key as a 128-bit or 80-bit bytes
        rounds: the number of rounds as an integer, 32 by default
        """
        self.rounds = rounds
        key_int = int.from_bytes(key, byteorder="big")
        if len(key) * 8 == 80:
            self.roundkeys = generateRoundkeys80(key_int, self.rounds)
        elif len(key) * 8 == 128:
            self.roundkeys = generateRoundkeys128(key_int, self.rounds)
        else:
            raise ValueError("Key must be a 128-bit or 80-bit bytes")

    def encrypt(self, block):
        """Encrypt 1 block (8 bytes)

        Input:  plaintext block as bytes
        Output: ciphertext block as bytes
        """
        state = int.from_bytes(block, byteorder="big")
        for i in range(self.rounds - 1):
            state = addRoundKey(state, self.roundkeys[i])
            state = sBoxLayer(state)
            state = pLayer(state)
        cipher = addRoundKey(state, self.roundkeys[-1])
        return cipher.to_bytes(8, byteorder="big")

    def decrypt(self, block):
        """Decrypt 1 block (8 bytes)

        Input:  ciphertext block as bytes
        Output: plaintext block as bytes
        """
        state = int.from_bytes(block, byteorder="big")
        for i in range(self.rounds - 1):
            state = addRoundKey(state, self.roundkeys[-i - 1])
            state = pLayer_dec(state)
            state = sBoxLayer_dec(state)
        decipher = addRoundKey(state, self.roundkeys[0])
        return decipher.to_bytes(8, byteorder="big")

    def get_block_size(self):
        return 8


# 0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
Sbox = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
Sbox_inv = [Sbox.index(x) for x in range(16)]
PBox = [
    0,
    16,
    32,
    48,
    1,
    17,
    33,
    49,
    2,
    18,
    34,
    50,
    3,
    19,
    35,
    51,
    4,
    20,
    36,
    52,
    5,
    21,
    37,
    53,
    6,
    22,
    38,
    54,
    7,
    23,
    39,
    55,
    8,
    24,
    40,
    56,
    9,
    25,
    41,
    57,
    10,
    26,
    42,
    58,
    11,
    27,
    43,
    59,
    12,
    28,
    44,
    60,
    13,
    29,
    45,
    61,
    14,
    30,
    46,
    62,
    15,
    31,
    47,
    63,
]
PBox_inv = [PBox.index(x) for x in range(64)]


def generateRoundkeys80(key, rounds):
    """Generate the roundkeys for a 80-bit key

    Input:
            key:    the key as a 80-bit integer
            rounds: the number of rounds as an integer
    Output: list of 64-bit roundkeys as integers"""
    roundkeys = []
    for i in range(1, rounds + 1):  # (K1 ... K32)
        # rawkey: used in comments to show what happens at bitlevel
        # rawKey[0:64]
        roundkeys.append(key >> 16)
        # 1. Shift
        # rawKey[19:len(rawKey)]+rawKey[0:19]
        key = ((key & (2**19 - 1)) << 61) + (key >> 19)
        # 2. SBox
        # rawKey[76:80] = S(rawKey[76:80])
        key = (Sbox[key >> 76] << 76) + (key & (2**76 - 1))
        # 3. Salt
        # rawKey[15:20] ^ i
        key ^= i << 15
    return roundkeys


def generateRoundkeys128(key, rounds):
    """Generate the roundkeys for a 128-bit key

    Input:
            key:    the key as a 128-bit integer
            rounds: the number of rounds as an integer
    Output: list of 64-bit roundkeys as integers"""
    roundkeys = []
    for i in range(1, rounds + 1):  # (K1 ... K32)
        # rawkey: used in comments to show what happens at bitlevel
        roundkeys.append(key >> 64)
        # 1. Shift
        key = ((key & (2**67 - 1)) << 61) + (key >> 67)
        # 2. SBox
        key = (
            (Sbox[key >> 124] << 124)
            + (Sbox[(key >> 120) & 0xF] << 120)
            + (key & (2**120 - 1))
        )
        # 3. Salt
        # rawKey[62:67] ^ i
        key ^= i << 62
    return roundkeys


def addRoundKey(state, roundkey):
    return state ^ roundkey


def sBoxLayer(state):
    """SBox function for encryption

    Input:  64-bit integer
    Output: 64-bit integer"""

    output = 0
    for i in range(16):
        output += Sbox[(state >> (i * 4)) & 0xF] << (i * 4)
    return output


def sBoxLayer_dec(state):
    """Inverse SBox function for decryption

    Input:  64-bit integer
    Output: 64-bit integer"""
    output = 0
    for i in range(16):
        output += Sbox_inv[(state >> (i * 4)) & 0xF] << (i * 4)
    return output


def pLayer(state):
    """Permutation layer for encryption

    Input:  64-bit integer
    Output: 64-bit integer"""
    output = 0
    for i in range(64):
        output += ((state >> i) & 0x01) << PBox[i]
    return output


def pLayer_dec(state):
    """Permutation layer for decryption

    Input:  64-bit integer
    Output: 64-bit integer"""
    output = 0
    for i in range(64):
        output += ((state >> i) & 0x01) << PBox_inv[i]
    return output


def _test():
    import doctest

    doctest.testmod()


# if __name__ == "__main__":
#     key = bytes.fromhex("0123456789abcdef0123456789abcdef")
#     plain_1 = b"1weqweqd"
#     plain_2 = b"23444444"
#     plain_3 = b"dddd2225"
#     print(plain_1)
#     print(plain_2)
#     print(plain_3)
#     cipher = PresentCipher(key)
#     encrypted_1 = cipher.encrypt(plain_1)
#     encrypted_2 = cipher.encrypt(plain_2)
#     encrypted_3 = cipher.encrypt(plain_3)
#     enc_1 = encrypted_1.hex()
#     enc_2 = encrypted_2.hex()
#     enc_3 = encrypted_3.hex()
#     print(enc_1)
#     print(enc_2)
#     print(enc_3)

#     decrypted_1 = cipher.decrypt(encrypted_1)
#     decrypted_2 = cipher.decrypt(encrypted_2)
#     decrypted_3 = cipher.decrypt(encrypted_3)
#     decr_1 = decrypted_1
#     decr_2 = decrypted_2
#     decr_3 = decrypted_3
#     print(decr_1)
#     print(decr_2)
#     print(decr_3)


class Present(BlockCipher):
    BLOCK_SIZE = 64
    KEY_SIZE = 128

    def __init__(self, key: "str | bytes | list | tuple", validate_key=False):
        super().__init__()

        # make sure the key is in bytes
        if isinstance(key, str):
            key = bytes.fromhex(key)
        elif isinstance(key, (list, tuple)):
            key = bytes(key)

        self.key = key
        self.cipher = PresentCipher(key)

    def encrypt(self, plaintext: "str | bytes | list | tuple | int"):
        # the cipher only accepts bytes
        # so we convert the plaintext to bytes
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        elif isinstance(plaintext, (list, tuple)):
            plaintext = bytes(plaintext)
        elif isinstance(plaintext, int):
            plaintext = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, "big")
        return self.cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: "str | bytes | list | tuple | int"):
        # the cipher only accepts bytes
        # so we convert the ciphertext to bytes
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode()
        elif isinstance(ciphertext, (list, tuple)):
            ciphertext = bytes(ciphertext)
        elif isinstance(ciphertext, int):
            ciphertext = ciphertext.to_bytes((ciphertext.bit_length() + 7) // 8, "big")
        return self.cipher.decrypt(ciphertext)


import secrets

if __name__ == "__main__":
    cipher = Present(secrets.randbits(128).to_bytes(16))
    g = cipher.encrypt(secrets.randbits(64).to_bytes(8))
    print(g)
    print(cipher.decrypt(g))
    print(type(g))
