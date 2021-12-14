import hashlib
import hmac

# hmac help us to to use any ordinary hash funtion as it were keyed
# hash function An HMAC need three inputs: key, message and crypto
# hash function. Key and Message are byte

def hmac_f(key, data, hash_function):
    return hmac.new(key=key, msg=data, digestmod=hash_function)


if __name__ == '__main__':
    passed_key = b'Eduardo Santos'
    passed_msg = b'This is the message or data'
    passed_hash_funtion = hashlib.sha3_256
    hmac_f_implemented = hmac_f(
                                key=passed_key,
                                data=passed_msg,
                                hash_funtion=passed_hash_funtion)
    print(f'hmac function digest {hmac_f_implemented.digest()}')
    print(f'hmac function hexa {hmac_f_implemented.hexdigest()}')