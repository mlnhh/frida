import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

KEY = bytes([
    0xF1,0x3E,0x5A,0x80,0x9D,0x29,0xC1,0x6B,0x3D,0xD8,0xA4,0x17,0x6A,0xF5,0x58,0x01,
    0xC6,0x82,0x02,0x36,0x4D,0xD3,0xB9,0xC5,0xFB,0x13,0x09,0x8B,0x75,0x07,0x33,0x71
])

def encrypt_payload():
    with open("load.lebronjs", "rb") as f:
        plaintext = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(".w", "wb") as f:
        f.write(iv + ciphertext)

if __name__ == "__main__":
    encrypt_payload()
