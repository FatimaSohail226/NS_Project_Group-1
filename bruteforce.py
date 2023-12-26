import time
import ipaddress
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from binascii import unhexlify

# Pseudonym from your dataset (AES-256 encrypted hash)
pseudonym = "c8dbc83acad0cdf89177471f3c9e256d41392dd4e7a45dc6d49ea9b34217a945"
pseudonym_bytes = unhexlify(pseudonym)

# Base IPv6 address prefix
base_ipv6 = "2001:db8::"

print("Attempting to decrypt pseudonym:", pseudonym)


def is_valid_ipv6_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def attempt_decrypt(encrypted_data):
    try:
        # Generate a random 256-bit (32-byte) key
        key = os.urandom(32)
        print("Generated a new 256-bit key for decryption.")
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()

        # First decryption pass
        print("Performing the first decryption...")
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Second decryption pass with the same key
        decryptor = cipher.decryptor()
        print("Performing the second decryption...")
        decrypted_data = decryptor.update(decrypted_data) + decryptor.finalize()

        if is_valid_ipv6_address(decrypted_data.decode()):
            print("Valid IPv6 address found.")
            return decrypted_data.decode()
        else:
            print(
                "Decryption attempt unsuccessful. Result is not a valid IPv6 address."
            )
            return None
    except Exception as e:
        print("Error during decryption attempt:", e)
        return None


# Set a 9-second timer
start_time = time.time()
attempt_count = 0
while time.time() - start_time < 9:
    print(f"Attempt {attempt_count}: Starting decryption process...")
    result = attempt_decrypt(pseudonym_bytes)
    if result is not None:
        print("Decryption successful. Found valid IPv6 address:", result)
        break
    attempt_count += 1
else:
    print(
        "Failed to decrypt the pseudonym to find key within 9 seconds. Total attempts:",
        attempt_count,
    )
