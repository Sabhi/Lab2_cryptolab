#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii


def print_hex(label, data):
    """Print binary data as a readable hexadecimal string."""
    print(f"{label}: {binascii.hexlify(data).decode()}")


def main():
    print("=" * 60)
    print("AES-CBC Mode Demonstration")
    print("=" * 60)

    # This is a Random 128-bit key.
    key = get_random_bytes(16)
    print_hex("Key", key)

    # This is a Random 128bit IV
    iv = get_random_bytes(16)
    print_hex("IV", iv)
   
   #This is a Plain text with padding. 
    plaintext = b"Meeting notes: budget approval pending."
    print(f"Plaintext: {plaintext}")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    print_hex("Ciphertext (CBC)", ciphertext)

    # The Receiver willuse the same key and the same IV
    decipher = AES.new(key, AES.MODE_CBC, iv)
    recovered = unpad(decipher.decrypt(ciphertext), AES.block_size)
    print(f"Recovered (correct IV): {recovered}")
    assert recovered == plaintext
    print("Decryption with correct IV successful.\n")

    # This is a IV REUSE ATTACK.
    print("--- IV Reuse Attack Demo ---")

    # Two messages that share the same first 16-byte block.
    msg1 = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
    msg2 = b"AAAAAAAAAAAAAAAACCCCCCCCCCCCCCCC"

    # We will encrypt both with the same key and the SAME IV intentially.
    cipher1 = AES.new(key, AES.MODE_CBC, iv)
    ct1 = cipher1.encrypt(pad(msg1, AES.block_size))

    cipher2 = AES.new(key, AES.MODE_CBC, iv)   # Here, we are using same IV
    ct2 = cipher2.encrypt(pad(msg2, AES.block_size))

    print_hex("CT1 (same IV)", ct1)
    print_hex("CT2 (same IV)", ct2)

    # As we used the same first plaintext blocks and the same IV so the first ciphertext blocks are same.
    xor_ct = bytes(a ^ b for a, b in zip(ct1[:16], ct2[:16]))
    xor_pt = bytes(a ^ b for a, b in zip(msg1[:16], msg2[:16]))

    print_hex("CT1 XOR CT2 (first block)", xor_ct)
    print_hex("PT1 XOR PT2 (first block)", xor_pt)


if __name__ == "__main__":
    main()
