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
    print("AES-ECB Mode Demonstration")
    print("=" * 60)

    # This is a Random 128-bit key.
    key = get_random_bytes(16)
    print_hex("Key (16 bytes)", key)

    # This is a 32 byte plaintext that contains two same 16-byte blocks.
    plaintext = b"CryptoLabBlock!!" * 2 
    print(f"Plaintext: {plaintext}")
    print(f"Plaintext length: {len(plaintext)} bytes")

    # ----- Encryption will start from here-----
    cipher = AES.new(key, AES.MODE_ECB)

    # We will use pad() fucntion to adds PKCS7 padding so the length becomes a multiple of 16 then encrypt the padded data.
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    print_hex("Ciphertext (ECB)", ciphertext) # Here we have first 16 bytes of ciphertext are same to the next 16 bytes as the plain text blocks were same.

    # ----- Decryption will start from here -----
   
    # We are creating a new cipher object with the same key and mode.
    decipher = AES.new(key, AES.MODE_ECB)

    # Decrypt, then remove the PKCS7 padding to recover the original message.
    recovered = unpad(decipher.decrypt(ciphertext), AES.block_size)
    print(f"\nRecovered plaintext: {recovered}")

    # Verify correctness.
    assert recovered == plaintext
    print("Decryption successful – plaintext matches with original.")

if __name__ == "__main__":
    main()
