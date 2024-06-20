from .core import BlockCipher
from .raw_cipher.present import PresentCipher


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
