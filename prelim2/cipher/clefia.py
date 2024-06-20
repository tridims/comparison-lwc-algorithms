from .core import BlockCipher
from .raw_cipher.clefia import setKey, enc, dec


class Clefia(BlockCipher):
    BLOCK_SIZE = 128
    KEY_SIZE = 256

    def __init__(self, key: "str | bytes | list | tuple", validate_key=False):
        super().__init__()
        if isinstance(key, str):
            key = bytes.fromhex(key)
        elif isinstance(key, (list, tuple)):
            key = bytes(key)
        if validate_key:
            if len(key) * 8 != self.KEY_SIZE:
                raise ValueError("Invalid key size")
        self.key = int.from_bytes(key, "big")  # Convert bytes to integer
        setKey(self.key, "SIZE_256")

    def encrypt(self, plaintext: "str | bytes | list | tuple") -> bytes:
        if isinstance(plaintext, str):
            plaintext = bytes.fromhex(plaintext)
        if len(plaintext) * 8 != self.BLOCK_SIZE:
            raise ValueError("Invalid block size")
        return enc(int.from_bytes(plaintext, "big")).to_bytes(
            self.BLOCK_SIZE // 8, "big"
        )

    def decrypt(self, ciphertext: "str | bytes | list | tuple") -> bytes:
        if isinstance(ciphertext, str):
            ciphertext = bytes.fromhex(ciphertext)
        if len(ciphertext) * 8 != self.BLOCK_SIZE:
            raise ValueError("Invalid block size")
        return dec(int.from_bytes(ciphertext, "big")).to_bytes(
            self.BLOCK_SIZE // 8, "big"
        )


import secrets

if __name__ == "__main__":
    key1 = 0xFFEEDDCCBBAA99887766554433221100
    cipher = Clefia(secrets.token_bytes(32))
    g = cipher.encrypt(secrets.token_bytes(16))
    print(g)
    print(cipher.decrypt(g))
    print(type(g))
