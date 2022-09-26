"""
    HMAC is generic way to use the ordinary hashing tool
    this not generate a strong hash token if you wanna to
    implemanted a strong hash token use fernet instead
"""
import hashlib
import hmac
import json


def hmac_sender(shared_key, data, digestmod=hashlib.sha3_256):
    """
        this funtion send a json element with to values
        a message and hash value, to default using the sha3_256 algorithm
        but you can send the hashlib algorithm you prefer
    """
    hmac_sha3_256 = hmac.new(key=shared_key, msg=data, digestmod=digestmod)
    hash_value = hmac_sha3_256.hexdigest()
    auth_msg = {
        'message':list(data),
        'hash_value':hash_value
    }
    return json.dumps(auth_msg)


def hmac_receiver(shared_key, auth_data, digestmod=hashlib.sha3_256):
    """
        receive a message with public key and the ciphering algorithm
    """
    auth_msg = json.loads(auth_data)
    message = bytes(auth_msg['message'])
    hmac_sha3_256 = hmac.new(key=shared_key, msg=message, digestmod=digestmod)
    hash_value = hmac_sha3_256.hexdigest()
    return hmac.compare_digest(hash_value, auth_msg['hash_value'])
