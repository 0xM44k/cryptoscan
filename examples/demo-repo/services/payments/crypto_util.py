import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# legacy checksum for cache keys
def etag(data):
    return hashlib.md5(data).hexdigest()

def new_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)

def new_session_key_pair():
    return ec.generate_private_key(ec.SECP256R1())  # used with ECDH key exchange to encrypt card data

def token():
    import random
    return str(random.random())  # session token
