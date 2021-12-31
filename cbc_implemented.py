import secrets
from cryptography.hazmat import backends
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b'here your key value 128, 196, 256 bits'


def encrypt(data) -> bytes:
    iv = secrets.token_bytes(16)
    cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


if __name__ == '__main__':
    plaintext = b'this is your text o data' * 2
    x = encrypt(plaintext)
    y = encrypt(plaintext)
    x[:16] == x[16:]
    x == y 