import secrets
from cipher.speck import Speck
from cipher.present import Present
from cipher.clefia import Clefia
from operation import MODE_OF_OPERATIONS_DICT, operate_block_mode

if __name__ == "__main__":
    plaintext = "Some dummy data to encrypt and decrypt to use for the testing purposes of the implemented cipher with the selected block mode."

    print("Testing Speck")
    for mode in MODE_OF_OPERATIONS_DICT:
        key_size = Speck.KEY_SIZE
        key = secrets.token_bytes(key_size >> 3)
        base_cipher = Speck(key, validate_key=False)
        operate_block_mode(mode, base_cipher, plaintext)

    print("Testing Present")
    for mode in MODE_OF_OPERATIONS_DICT:
        key_size = Present.KEY_SIZE
        key = secrets.token_bytes(key_size >> 3)
        base_cipher = Present(key, validate_key=False)
        operate_block_mode(mode, base_cipher, plaintext)

    print("Testing Clefia")
    for mode in MODE_OF_OPERATIONS_DICT:
        key_size = Clefia.KEY_SIZE
        key = secrets.token_bytes(key_size >> 3)
        base_cipher = Clefia(key, validate_key=False)
        operate_block_mode(mode, base_cipher, plaintext)

    print("All modes of operation have been tested successfully.")
