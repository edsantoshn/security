from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def generation_key_pair() -> tuple(rsa.RSAPublicKey, rsa.RSAPrivateKey):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    public_key = private_key.public_key()
    return tuple(public_key, private_key)


def serialization_key_pair(private_key, public_key) -> bool:
    ## first genere the private key file
    ## secondly genere the public key file
    ## if all okey return True else raise an exception
    try:
        private_bytes = private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption())
        with open('private_key.PEM', 'xb') as private_file:
            private_file.write(private_bytes)

        public_bytes = public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        with open('public_key.PEM', 'xb') as public_file:
            public_file.write(public_bytes)
    except Exception as ex:
        raise ex
    else:
        return True


def deserialization_files(private_key_file=None, public_key_file=None) -> dict(bytes, bytes):
    load_public_key, load_private_key = None, None
    if private_key_file:
        with open(private_key_file, 'rb') as private_file:
            load_private_key = serialization.load_pem_private_key(
                                private_file.read(),
                                backend=default_backend())
    
    if public_key_file:
        with open(public_key_file, 'rb') as public_file:
            load_public_key = serialization.load_pem_public_key(
                    public_file.read(),
                    backend=default_backend
            )
    
    return {'public_key':load_public_key, 'private_key':load_private_key}



def encrypting_data(data, public_key) -> dict(bytes, bytes):
    padding_config = padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None)
    ciphertext = public_key.encrypt(plaintext=data, padding=padding_config)
    return {'data':ciphertext, 'public_key':public_key}


def decryting_data(ciphertext, private_key) -> str:
    padding_config = padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None)
    plaintext = private_key.decrypt(ciphertext=ciphertext, padding=padding_config)
    return plaintext

