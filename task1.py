from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# -- START OF YOUR CODERUNNER SUBMISSION CODE
# INCLUDE MODULES
# INCLUDE HELPER FUNCTIONS YOU IMPLEMENT

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

    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv_bytes), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(data_bytes) + encryptor.finalize()

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

    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv_bytes), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()

    return plaintext.decode('utf-8')


# -- END OF YOUR CODERUNNER SUBMISSION CODE
