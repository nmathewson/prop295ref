
# This part uses the Cryptodome drop-in replacement for PyCrypto to
# try to get a reasonable set of crypto primitives.

__all__ = [ "block_encrypt", "block_decrypt",
            "digest", "stream_crypt",
            "stream_encrypt", "stream_decrypt" ]

from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from util import xor

# Cryptodome doesn't expose ghash intentionally, but we can grab it
# by using an undocumented module.  Thanks, Cryptodome!
import Cryptodome.Cipher._mode_gcm as gcm_kludge

if gcm_kludge._ghash_clmul is not None:
    ghash_impl = gcm_kludge._ghash_clmul
else:
    ghash_impl = gcm_kludge._ghash_portable

def digest(key, value):
    """
    Return the GHASH of 'value', using 'key'.  Pads value with zeros
    to an even multiple of 16 bytes.
    """
    d = gcm_kludge._GHASH(key, ghash_impl)
    if len(value) & 15 != 0:
        padding_bytes = 16 - (len(value) & 15)
        value += b"\0" * padding_bytes
    d.update(value)
    return d.digest()

def block_encrypt(key, value):
    """Encrypt a single block 'value' with the AES key 'key'."""
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(value)

def block_decrypt(key, value):
    """Decrypt a single block 'value' with the AES key 'key'."""
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(value)

def stream_crypt(key, iv, plaintext):
    """Encrypt/decrypt a bytestream 'plaintext' using AES-CTR with the provided
       key and IV.
    """
    ctr = Counter.new(nbits=128, initial_value=int.from_bytes(iv, "big"))
    aes = AES.new(key, AES.MODE_CTR, counter = ctr)
    return aes.encrypt(plaintext)

# Aliases for stream_crypt.
stream_encrypt = stream_decrypt = stream_crypt
