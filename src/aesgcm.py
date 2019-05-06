
# This part uses the Cryptodome drop-in replacement for PyCrypto to
# try to get a reasonable set of crypto primitives.

__all__ = [ "block_crypt", "block_encrypt", "block_decrypt",
            "digest", "stream", "stream_crypt",
            "stream_encrypt", "stream_decrypt" ]

from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from util import xor

import Cryptodome.Cipher._mode_gcm as gcm_kludge


if gcm_kludge._ghash_clmul is not None:
    ghash_impl = gcm_kludge._ghash_clmul
else:
    ghash_impl = gcm_kludge._ghash_portable

def digest(key, value):
    d = gcm_kludge._GHASH(key, ghash_impl)
    if len(value) & 15 != 0:
        padding_bytes = 16 - (len(value) & 15)
        value += b"\0" * padding_bytes
    d.update(value)
    return d.digest()

def block_crypt(key, value, encrypt):
    aes = AES.new(key, AES.MODE_ECB)
    if encrypt:
        result = aes.encrypt(value)
    else:
        result = aes.decrypt(value)
    return result

def block_encrypt(key, value):
    return block_crypt(key, value, True)

def block_decrypt(key, value):
    return block_crypt(key, value, False)

def stream(key, iv, length):
    ctr = Counter.new(nbits=128, initial_value=int.from_bytes(iv, "big"))
    aes = AES.new(key, AES.MODE_CTR, counter = ctr)
    return aes.encrypt(b"\0"*length)

def stream_crypt(key, iv, plaintext):
    return xor(plaintext, stream(key, iv, len(plaintext)))

stream_encrypt = stream_decrypt = stream_crypt
