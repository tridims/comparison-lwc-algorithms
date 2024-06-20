import secrets
import traceback
import modes
from cipher import des
from cipher.core import BlockCipher

MODE_OF_OPERATIONS = {
    "ECB": modes.ElectronicCodeBookMode,
    "CBC": modes.CipherBlockChainingMode,
    "CFB": modes.CipherFeedBackMode,
    "OFB": modes.OutputFeedBackMode,
    "CTR": modes.CounterMode,
}


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


def operate_block_mode(mode, base_cipher: BlockCipher, plaintext, key):
    block_size = base_cipher.BLOCK_SIZE

    try:
        mode_of_operation_args = {"cipher": base_cipher}
        mode_of_operation_args["block_size"] = block_size
        mode_cipher = MODE_OF_OPERATIONS[mode](**mode_of_operation_args)

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


if __name__ == "__main__":
    key_size = des.DES.KEY_SIZE
    key = secrets.token_bytes(key_size >> 3)
    base_cipher = des.DES(key, validate_key=False)
    plaintext = "Some dummy data to encrypt and decrypt because the user did not specify any input."

    for mode in MODE_OF_OPERATIONS:
        operate_block_mode(mode, base_cipher, plaintext, key)

    print("All modes of operation have been tested successfully.")
