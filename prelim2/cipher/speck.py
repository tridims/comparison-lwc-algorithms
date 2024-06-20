from __future__ import print_function

from core import BlockCipher


class SpeckCipher(object):
    """Speck Block Cipher Object"""

    # valid cipher configurations stored:
    # block_size:{key_size:number_rounds}
    __valid_setups = {
        32: {64: 22},
        48: {72: 22, 96: 23},
        64: {96: 26, 128: 27},
        96: {96: 28, 144: 29},
        128: {128: 32, 192: 33, 256: 34},
    }

    def encrypt_round(self, x, y, k):
        """Complete One Round of Feistel Operation"""
        rs_x = (
            (x << (self.word_size - self.alpha_shift)) + (x >> self.alpha_shift)
        ) & self.mod_mask

        add_sxy = (rs_x + y) & self.mod_mask

        new_x = k ^ add_sxy

        ls_y = (
            (y >> (self.word_size - self.beta_shift)) + (y << self.beta_shift)
        ) & self.mod_mask

        new_y = new_x ^ ls_y

        return new_x, new_y

    def decrypt_round(self, x, y, k):
        """Complete One Round of Inverse Feistel Operation"""

        xor_xy = x ^ y

        new_y = (
            (xor_xy << (self.word_size - self.beta_shift)) + (xor_xy >> self.beta_shift)
        ) & self.mod_mask

        xor_xk = x ^ k

        msub = ((xor_xk - new_y) + self.mod_mask_sub) % self.mod_mask_sub

        new_x = (
            (msub >> (self.word_size - self.alpha_shift)) + (msub << self.alpha_shift)
        ) & self.mod_mask

        return new_x, new_y

    def __init__(self, key, key_size=128, block_size=128):

        # Setup block/word size
        try:
            self.possible_setups = self.__valid_setups[block_size]
            self.block_size = block_size
            self.word_size = self.block_size >> 1
        except KeyError:
            print("Invalid block size!")
            print(
                "Please use one of the following block sizes:",
                [x for x in self.__valid_setups.keys()],
            )
            raise

        # Setup Number of Rounds and Key Size
        try:
            self.rounds = self.possible_setups[key_size]
            self.key_size = key_size
        except KeyError:
            print("Invalid key size for selected block size!!")
            print(
                "Please use one of the following key sizes:",
                [x for x in self.possible_setups.keys()],
            )
            raise

        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = (2**self.word_size) - 1

        # Mod mask for modular subtraction
        self.mod_mask_sub = 2**self.word_size

        # Setup Circular Shift Parameters
        if self.block_size == 32:
            self.beta_shift = 2
            self.alpha_shift = 7
        else:
            self.beta_shift = 3
            self.alpha_shift = 8

        # Parse the given key and truncate it to the key length
        try:
            self.key = key & ((2**self.key_size) - 1)
        except (ValueError, TypeError):
            print("Invalid Key Value!")
            print("Please Provide Key as int")
            raise

        # Pre-compile key schedule
        self.key_schedule = [self.key & self.mod_mask]
        l_schedule = [
            (self.key >> (x * self.word_size)) & self.mod_mask
            for x in range(1, self.key_size // self.word_size)
        ]

        for x in range(self.rounds - 1):
            new_l_k = self.encrypt_round(l_schedule[x], self.key_schedule[x], x)
            l_schedule.append(new_l_k[0])
            self.key_schedule.append(new_l_k[1])

    def encrypt(self, plaintext):
        try:
            b = (plaintext >> self.word_size) & self.mod_mask
            a = plaintext & self.mod_mask
        except TypeError:
            print("Invalid plaintext!")
            print("Please provide plaintext as int")
            raise

        b, a = self.encrypt_function(b, a)
        ciphertext = (b << self.word_size) + a

        return ciphertext

    def decrypt(self, ciphertext):
        try:
            b = (ciphertext >> self.word_size) & self.mod_mask
            a = ciphertext & self.mod_mask
        except TypeError:
            print("Invalid ciphertext!")
            print("Please provide plaintext as int")
            raise

        b, a = self.decrypt_function(b, a)
        plaintext = (b << self.word_size) + a
        return plaintext

    def encrypt_function(self, upper_word, lower_word):

        x = upper_word
        y = lower_word

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in self.key_schedule:
            rs_x = (
                (x << (self.word_size - self.alpha_shift)) + (x >> self.alpha_shift)
            ) & self.mod_mask

            add_sxy = (rs_x + y) & self.mod_mask

            x = k ^ add_sxy

            ls_y = (
                (y >> (self.word_size - self.beta_shift)) + (y << self.beta_shift)
            ) & self.mod_mask

            y = x ^ ls_y

        return x, y

    def decrypt_function(self, upper_word, lower_word):

        x = upper_word
        y = lower_word

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in reversed(self.key_schedule):
            xor_xy = x ^ y

            y = (
                (xor_xy << (self.word_size - self.beta_shift))
                + (xor_xy >> self.beta_shift)
            ) & self.mod_mask

            xor_xk = x ^ k

            msub = ((xor_xk - y) + self.mod_mask_sub) % self.mod_mask_sub

            x = (
                (msub >> (self.word_size - self.alpha_shift))
                + (msub << self.alpha_shift)
            ) & self.mod_mask

        return x, y


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
