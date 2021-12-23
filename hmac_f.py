import hashlib
import hmac
import json

def hmac_sender(shared_key, data, digestmod=hashlib.sha3_256):
    hmac_sha3_256 = hmac.new(key=shared_key, msg=data, digestmod=digestmod)
    hash_value = hmac_sha3_256.hexdigest()
    auth_msg = {
        'message':list(data),
        'hash_value':hash_value
    }
    return json.dumps(auth_msg)


def hmac_receiver(shared_key, auth_data, digestmod=hashlib.sha3_256):
    auth_msg = json.loads(auth_data)
    message = bytes(auth_msg['message'])
    hmac_sha3_256 = hmac.new(key=shared_key, msg=message, digestmod=digestmod)
    hash_value = hmac_sha3_256.hexdigest()
    return hmac.compare_digt(hash_value, auth_msg['hash_value'])
    



