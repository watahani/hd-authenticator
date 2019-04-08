from math import log2
import hmac
import hashlib
import ecdsa

def hmac512(key, source):
    if isinstance(source, str):
        source = source.encode()
    if isinstance(key, str):
        key = key.encode()
    return hmac.new(key, source, hashlib.sha512).digest()

def prikey_and_ccode(key, seed):
    ''' generate ECDSA private key of ecdsa lib and chain code as string'''
    hmac = hmac512(key, seed)
    prikey = hmac[:32]
    prikey = ecdsa.SigningKey.from_string(prikey, curve=ecdsa.SECP256k1)
    ccode = hmac[32:]
    return prikey, ccode


def add_secret_keys(*args, order):
    '''add bytes secrets as int and return new bytes'''
    prikey = 0

    for key in args:
        if prikey == 0:
            prikey = int.from_bytes(key, "big")
        else:
            prikey = (prikey + int.from_bytes(key, "big")) % order

    return prikey.to_bytes( int(log2(order)/8), 'big')

def int_from_bytes(key):
    return int.from_bytes(key, "big")


def deltakey_and_ccode(index, pubkey, ccode):
    source = pubkey + index
    deltakey, child_ccode = prikey_and_ccode(key=ccode, seed=source)
    return deltakey, child_ccode
