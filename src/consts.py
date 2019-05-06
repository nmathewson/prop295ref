
# The digest is GHASH: it has a 16-byte key and a 16 byte output.
DIG_KEY_LEN = 16
DIGEST_LEN = 16

# The block cipher is AES256: it has a 32-byte key and a 16-byte block size
BLOCK_KEY_LEN = 32
BLOCK_LEN = 16

# The stream cipher is AES256_CTR: it has a 32-byte key, and a 16-byte IV.
STREAM_KEY_LEN = 32
STREAM_IV_LEN = 16

# Length of a Tor cell's payload.
PAYLOAD_LEN = 509

# The length of one "S" value in the protocol.
TAG_LEN = BLOCK_LEN

# longest possible length for the non-tag part of a relay cell
MAX_MSG_LEN = PAYLOAD_LEN - TAG_LEN
