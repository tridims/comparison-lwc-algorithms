from .core import BlockCipher
from .raw_cipher.speck import SpeckCipher


# Wrapper class that will be used in the main code
class Speck(BlockCipher):
    BLOCK_SIZE = 128
    KEY_SIZE = 256

    def __init__(self, key: "str | bytes | list | tuple", validate_key=False):
        super().__init__()

        # make sure the key is in int
        if isinstance(key, (str, bytes)):
            key = int.from_bytes(key, "big")
        elif isinstance(key, (list, tuple)):
            key = int.from_bytes(bytes(key), "big")

        self.key = key
        self.cipher = SpeckCipher(key, self.KEY_SIZE, self.BLOCK_SIZE)

    def encrypt(self, plaintext: "str | bytes | list | tuple"):
        # the cipher only accepts integers
        # so we convert the plaintext to an integer
        if isinstance(plaintext, (str, bytes)):
            plaintext = int.from_bytes(plaintext, "big")
        elif isinstance(plaintext, (list, tuple)):
            plaintext = int.from_bytes(bytes(plaintext), "big")
        return self.cipher.encrypt(plaintext).to_bytes(self.BLOCK_SIZE >> 3, "big")

    def decrypt(self, ciphertext: "str | bytes | list | tuple"):
        # the cipher only accepts integers
        # so we convert the ciphertext to an integer
        if isinstance(ciphertext, (str, bytes)):
            ciphertext = int.from_bytes(ciphertext, "big")
        elif isinstance(ciphertext, (list, tuple)):
            ciphertext = int.from_bytes(bytes(ciphertext), "big")
        return self.cipher.decrypt(ciphertext).to_bytes(self.BLOCK_SIZE >> 3, "big")


import secrets

if __name__ == "__main__":
    cipher = Speck(secrets.randbits(256).to_bytes(32))
    g = cipher.encrypt(secrets.randbits(128).to_bytes(16))
    print(g)
    print(cipher.decrypt(g))
    print(type(g))
