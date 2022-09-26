"""
    Fernet is a simple high-level API is know as the recipes layer
    we can use it insted of Hazardous. FERNET encrypt methon
    hashed the ciphertext with HMAC SHA 256, returning a message
"""
from cryptography.fernet import Fernet, InvalidToken


KEY = Fernet.generate_key()

def fernet_encryting(data: bytes)-> bytes:
    """
        ciphering text with fernet, use a global
        key, returing a token with two elements
    """
    fernet = Fernet(KEY)
    token = fernet.encrypt(data)
    return token


def fernet_decrypting(token: bytes) ->bytes:
    """
        get the token, extrating the cipher text and do an
        authentication with HMAC SHA256
    """
    try:
        fernet = Fernet(KEY)
        data = fernet.decrypt(token)
    except InvalidToken as ex:
        raise f'error I can not decrypt the token: {ex}'
    else:
        return data
