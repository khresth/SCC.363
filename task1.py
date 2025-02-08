from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# -- START OF YOUR CODERUNNER SUBMISSION CODE
# INCLUDE MODULES

# INCLUDE HELPER FUNCTIONS YOU IMPLEMENT

def xor_bytes(a: bytes, b: bytes) -> bytes:
    length = min(len(a), len(b))
    result = bytearray(length)
    for i in range(length):
        result[i] = a[i] ^ b[i]
    return bytes(result)

'''
:param key: str: The hexadecimal value of a key to be used for encryption
:param iv: str: The hexadecimal value of an initialisation vector to be used for encryption
:param data: str: The data to be encrypted
:return: str: The hexadecimal value of encrypted data
'''
def Encrypt(key: str, iv: str, data: str) -> str:
    key_bytes = bytes.fromhex(key)
    iv_bytes = bytes.fromhex(iv)
    data_bytes = data.encode('utf-8')

    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = b""
    previous_block = iv_bytes

    for i in range(0, len(data_bytes), 16):
        block = data_bytes[i:i+16]
        encrypted_block = encryptor.update(previous_block)
        cipher_block = xor_bytes(encrypted_block[:len(block)], block)
        ciphertext += cipher_block
        previous_block = cipher_block

    return ciphertext.hex()


'''
:param key: str: The hexadecimal value of a key to be used for decryption
:param iv: str: The hexadecimal value of the initialisation vector to be used for decryption
:param data: str: The hexadecimal value of the data to be decrypted
:return: str: The decrypted data in UTF-8 format
'''
def Decrypt(key: str, iv: str, data: str) -> str:
    key_bytes = bytes.fromhex(key)
    iv_bytes = bytes.fromhex(iv)
    ciphertext_bytes = bytes.fromhex(data)

    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    decryptor = cipher.encryptor()

    plaintext = b""
    previous_block = iv_bytes

    for i in range(0, len(ciphertext_bytes), 16):
        block = ciphertext_bytes[i:i+16]
        encrypted_block = decryptor.update(previous_block)
        plain_block = xor_bytes(encrypted_block[:len(block)], block)
        plaintext += plain_block
        previous_block = block

    return plaintext.decode('utf-8').rstrip()

# -- END OF YOUR CODERUNNER SUBMISSION CODE
