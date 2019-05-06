
__all__ = [ "KDF" ]

from hashlib import shake_256

def kdf(secret_input, length):
    """Derive a length-byte key sequence from the 'secret-input'.

       Here we use SHAKE256 in preference to HKDF for speed
       and simplicity.
    """
    d = shake_256()
    d.update(secret_input)
    return d.digest(length)

class KDF:
    """A KDF object streams bytes from our kdf function."""
    def __init__(self, secret_input, output_len_max=1024):
        self.values = kdf(secret_input, output_len_max)

    def get(self, nBytes):
        assert len(self.values) >= nBytes
        result = self.values[:nBytes]
        self.values = self.values[nBytes:]
        return result
