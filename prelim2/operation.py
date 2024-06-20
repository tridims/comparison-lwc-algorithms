import traceback
from . import modes
from .cipher.core import BlockCipher

MODE_OF_OPERATIONS_DICT = {
    "ECB": modes.ElectronicCodeBookMode,
    "CBC": modes.CipherBlockChainingMode,
    "CFB": modes.CipherFeedBackMode,
    "OFB": modes.OutputFeedBackMode,
    "CTR": modes.CounterMode,
}

MODE_OF_OPERATIONS = [
    "ECB",
    "CBC",
    "CFB",
    "OFB",
    "CTR",
]


def operate_block_mode(mode, base_cipher: BlockCipher, plaintext):
    block_size = base_cipher.BLOCK_SIZE

    try:
        mode_of_operation_args = {"cipher": base_cipher}
        mode_of_operation_args["block_size"] = block_size
        mode_cipher = MODE_OF_OPERATIONS_DICT[mode](**mode_of_operation_args)

        plaintext = plaintext.encode()

        # Encrypt the plaintext
        ciphertext = bytearray()
        chunk_generator = modes.utils.block_generator(plaintext, block_size)
        for block_data in mode_cipher.encrypt(chunk_generator, debug=True):
            ciphertext += block_data["encrypted"]

        # Decrypt the ciphertext
        decrypted_plaintext = bytearray()
        ciphertext = bytes(ciphertext)
        chunk_generator = modes.utils.block_generator(ciphertext, block_size)

        for block_data in mode_cipher.decrypt(chunk_generator, debug=True):
            decrypted_plaintext += block_data["unpadded"]

        decrypted_plaintext = decrypted_plaintext.decode("utf-8")

        assert decrypted_plaintext == plaintext.decode(
            "utf-8"
        ), "Decrypted plaintext does not match original plaintext."

    except Exception as reason:
        print("X | error:", reason)
        traceback.print_exc()


def encrypt_using_block_mode(mode, base_cipher: BlockCipher, plaintext):
    block_size = base_cipher.BLOCK_SIZE

    try:
        mode_of_operation_args = {"cipher": base_cipher, "block_size": block_size}
        mode_cipher = MODE_OF_OPERATIONS_DICT[mode](**mode_of_operation_args)

        plaintext = plaintext.encode()

        # Encrypt the plaintext
        ciphertext = bytearray()
        chunk_generator = modes.utils.block_generator(plaintext, block_size)
        for block_data in mode_cipher.encrypt(chunk_generator, debug=True):
            ciphertext += block_data["encrypted"]

        return bytes(ciphertext)

    except Exception as reason:
        print("X | error:", reason)
        traceback.print_exc()
