from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# INCLUDE HELPER FUNCTIONS YOU IMPLEMENT
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

'''
:param plaintext1: str: This is Plaintext1
:param ciphertext1: bytes: This is the ciphertext of Plaintext1
:param plaintext2: str: This is Plaintext2
:return: bytes: The ciphertext of Plaintext2
'''
def attackAESMode(plaintext1: str, ciphertext1: bytes, plaintext2: str) -> bytes:
    plaintext1_bytes = plaintext1.encode()
    plaintext2_bytes = plaintext2.encode()

    keystring = xor_bytes(plaintext1_bytes, ciphertext1)
    keystream_16bits = keystring[:16]  
    forged_ciphertext = bytearray()
    plaintext2_length = len(plaintext2_bytes) 

    i = 0  
    while i < plaintext2_length:  
        block = plaintext2_bytes[i:i + 16]
        block_xor = xor_bytes(block, keystream_16bits)  
        forged_ciphertext.extend(block_xor)
        i += 16  

    return bytes(forged_ciphertext)
