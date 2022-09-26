"""
    CBC implementation
    this cipher the same plaintext twice and compare both of them
    getting as result false in every verification statement
"""

import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = b'4A5886EF4B3EE22855B4CB5A1ABC4'


def encrypt(data: bytes) -> bytes:
    """
        encrypt data with CBC algorithm, that generate two different ciphertext
        with identical plain text and same key. e.g. AES encryption
    """
    #random (16) bytes
    inicialization_vector = secrets.token_bytes(16)
    cipher = Cipher(
            algorithms.AES(KEY),
            modes.CBC(inicialization_vector),
            backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


if __name__ == '__main__':
    PLAINTEXT = b'this is your text o data' * 2
    x = encrypt(PLAINTEXT)
    y = encrypt(PLAINTEXT)
    #compare statements
    print(x[:16] == x[16:])
    print(x == y)
