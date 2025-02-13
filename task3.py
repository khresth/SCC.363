# -- START OF YOUR CODERUNNER SUBMISSION CODE
# INCLUDE MODULES
import hashlib
import os
# INCLUDE HELPER FUNCTIONS YOU IMPLEMENT

'''
param: data: bytes: The data to be hashed
return: bytes: The truncated hash
'''
def myHash(data: bytes) -> bytes:
    full_hash = hashlib.sha256(data).digest()

    half_len = len(full_hash) // 2
    first_half = full_hash[:half_len]
    second_half = full_hash[half_len:]

    xored_value = bytes(a ^ b for a, b in zip(first_half, second_half))

    half_len = len(xored_value) // 2
    first_half = xored_value[:half_len]
    second_half = xored_value[half_len:]

    xored_value = bytes(a ^ b for a, b in zip(first_half, second_half))

    half_len = len(xored_value) // 2
    first_half = xored_value[:half_len]
    second_half = xored_value[half_len:]

    xored_value = bytes(a ^ b for a, b in zip(first_half, second_half))

    return xored_value[:4]

'''
return: str: Return YES if myHash is secure and NO otherwise
'''
def myAttack() -> str:
    seen_hashes = {}
    for _ in range(500000):  
        input_data = os.urandom(16)  # Generate 16 random bytes as input
        hash_value = myHash(input_data)
        if hash_value in seen_hashes:
            return "NO"
        seen_hashes[hash_value] = input_data
    return "YES"

# -- END OF YOUR CODERUNNER SUBMISSION CODE
