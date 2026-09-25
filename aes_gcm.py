#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii

def print_hex(label, data):
    """Print binary data as a readable hexadecimal string."""
    print(f"{label}: {binascii.hexlify(data).decode()}")


def main():
  
    print("AES-GCM Mode (Authenticated Encryption)")
    
   # This is a Random 128-bit key.
    key = get_random_bytes(16)
    print_hex("Key", key)

    # We are using 12 bytes nonce size for GCM.
    nonce = get_random_bytes(12)
    print_hex("Nonce", nonce)

    # This is a secret data which we want to protect.
    plaintext = b"Secure packet payload protected by AES-GCM authenticated encryption."
    print(f"Plaintext: {plaintext}")

    # This is AAD authenticated but not encrypted
    aad = b"Additional Authenticated Data"
    print(f"AAD: {aad}")

    # ----- Encryption will start from here -----
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)                          # feed AAD into the authenticator
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    print_hex("Ciphertext", ciphertext)
    print_hex("Authentication Tag", tag)

    # ----- Decryption and verification here -----
    
    # We are using same key and same nonce and same AAD at the reciver side to decrypt and verify the authenticity of the data.
    decipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decipher.update(aad)

    try:
        # decrypt_and_verify raises ValueError if the tag does not match
        recovered = decipher.decrypt_and_verify(ciphertext, tag)
        print(f"Recovered (valid tag): {recovered}")
        print("Authentication successful – data was not tampered.\n")
    except ValueError as e:
        print(f"Verification failed: {e}")

    # NONCE REUSE.
    print("--- Nonce Reuse in GCM ---")

    # We are using intentially reuse the same nonce for two different messages fro demo purposes.
    nonce_reused = get_random_bytes(12)
    msg_a = b"Message A for GCM nonce reuse demonstration."
    msg_b = b"Message B for GCM nonce reuse demonstration."

    c1 = AES.new(key, AES.MODE_GCM, nonce=nonce_reused)
    ct_a, tag_a = c1.encrypt_and_digest(msg_a)

    c2 = AES.new(key, AES.MODE_GCM, nonce=nonce_reused)   # using same nonce
    ct_b, tag_b = c2.encrypt_and_digest(msg_b)

    print_hex("CT_A", ct_a)
    print_hex("CT_B", ct_b)

    # PREDICTABLE NONCE

    print("\n--- Predictable Nonce ---")
    predictable_nonce = b'\x00' * 12          # all zero nonce
    cipher_p = AES.new(key, AES.MODE_GCM, nonce=predictable_nonce)
    ct_p, tag_p = cipher_p.encrypt_and_digest(b"Predictable nonce is dangerous")
    print_hex("Ciphertext with zero nonce", ct_p)


if __name__ == "__main__":
    main()
