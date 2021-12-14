import hashlib
from pathlib import Path


def store(path, data, key):
    data_path = Path(path)

    hash_path = data_path.with_suffix('.hash')

    #Hashes document with the given key
    hash_value = hashlib.blake2b(data, key=key).hexdigest()

    #writes document and hash value to separete files
    with data_path.open(mode='x'), hash_path.open(mode='x'):
        data_path.write_bytes(data)
        hash_path.write_text(hash_value)


def is_modified(path, key):
    data_path = Path(path)
    hash_path = data_path.with_suffix('.hash')

    #read document and hash value from storage
    data = data_path.read_bytes()
    orgininal_hash_value = hash_path.read_text()
    
    #recomputes new hash value with the given key
    hash_value = hashlib.blake2b(data, key=key).hexdigest()

    #return True | False depending if recomputed hash value and hash value 
    #read from disks
    return orgininal_hash_value != hash_value