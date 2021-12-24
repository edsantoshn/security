## Fernet is a simple high-level API is know as the recipes layer
## we can use it insted of Hazardous

from cryptography.fernet import Fernet, InvalidToken


def fernet_encryting(data: bytes)-> bytes:
    key = Fernet.generate_key()
    fernet = Fernet(key)
    token = fernet.encrypt(data)
    return token


def fernet_decrypting(token: bytes) ->bytes:
    try:    
        key = Fernet.generate_key()
        fernet = Fernet(key)
        data = fernet.decrypt(token)
    except InvalidToken as ex:
        raise f'error I can not decrypt the token: {ex}'
    else:
        return data