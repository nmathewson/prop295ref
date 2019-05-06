"""Hello!

  This is an attempt to instantiate a version of the latest draft of
  proposal 295 in Python.  I usually find that the best way to see if
  I understand something is by implementing it, so here we go.

  Here are the changes I made:

    - I assumed that there are two separate values of T' shared with
      each hop: one forward, and one backward.

    - I assumed that when the formula in 3.1.1 refers to "T_0" in
      "Routing from the origin", it actually means "T_N".

    - I assumed that when 3.2.2 refers to M_I it actually means S_I.

    - I did not find the place where the proposal said how to
      initialize T_I, so I assume that it too can be derived from the
      KDF.

    - I removed DF and DB.

    - I changed the order of the keys within the KDF output, for
      convenience.

    - In 3.1.1, I assumed that Khf_siv and Ktf_siv are the keys shared
      with the particular target relay.

    - I'm dropping the two-byte "recognized" field.


  Additional notes:

    - I did not carefully follow all the +1 and -1 subscripts in the
      description, but rather used what I thought was intended.  If
      there are any bugs in the description, I won't have caught them
      with this.

    - This implementation does not actually implement GHASH, AES_CTR,
      or HKDF properly, since these aren't actually included as part
      of the PyCrypto library.  Instead, it does a deliberately bogus
      MAC, an AES_CTR with only 14 bytes of IV, and an extremely bogus
      KDF.

    - I tried to express the core functionality here in a way that
      makes sense for SIV.

"""

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


# block_crypt, stream_crypt, and digestfn are defined below, but you can
# ignore them.  They aren't what we actually want to use.

def xor(seq_a, seq_b):
    """ Return the xor of two sequences of bytes, which must be the same
        length.
    """
    assert len(seq_a) == len(seq_b)
    # XXXX doesn't work right on python2
    res = bytes(i ^ j for i,j in zip(seq_a, seq_b))
    return res

def zeros(n):
    """ Return a sequence of n zero bytes """
    return b"\00" * n

def zpad(seq, to_len):
    """ Pad 'seq' with zero bytes until it is 'to_len' bytes long. """
    assert len(seq) <= to_len
    return seq + zeros(to_len - len(seq))

def derive_nonce(key, encrypt, tweak, nonce):
    """ Compute a new nonce based on:

        key -- a block cipher key.
        encrypt -- a boolean.  True for encrypt, False for decrypt.
        tweak -- a value of T.
        nonce -- the old nonce.
    """
    return xor(tweak, block_crypt(key, xor(tweak, nonce), encrypt=encrypt))

class LayerKeys(object):
    """Stores one half the keys for a given layer.  The origin shares two
       of these with each hop in its circuit, one for each direction.

       These keys are immutable over the lifetime of a circuit.

         kt -- a block cipher key
         kh -- a hash key.

         k -- a stream cipher key.
    """
    def __init__(self, k, kh, kt):
        assert len(k) == STREAM_KEY_LEN
        assert len(kh) == DIG_KEY_LEN
        assert len(kt) == BLOCK_KEY_LEN

        self.k = k
        self.kh = kh
        self.kt = kt


class LayerState(object):
    """Stores one half of the mutable state for a given layer.  The
       origin shares two of these with each hop in its circuit, one for
       each direction.  It changes with every processed cell.

       initial_tweak -- a tweak value
    """
    def __init__(self, initial_tweak, initial_tprime):
        assert len(initial_tweak) == DIGEST_LEN
        #self.tweak = initial_tweak
        self.tprime = initial_tprime

def relay_crypt(keys, state, body, nonce, is_forward=True):
    """
       Compute the (forward or reverse) encryption of a body and nonce,
       as performed at a relay.
    """
    # compute the next tweak value. Note that + denotes concatenation.
    #   T_I = Digest(Khf_I,T'_I||C_I)
    # or
    #   T_I = Digest(Khb_I,T'_I||C_{I+1})
    tweak = digestfn(keys.kh, state.tprime + body)

    # save the tweak value.
    #   T'_I = T_I
    state.tprime = tweak

    # Compute the new value of S
    #   N_{I+1} = T_I ^ D(Ktf_I,T_I ^ N_I)
    # or
    #   N_I = T_I ^ E(Ktb_I,T_I ^ N_{I+1})
    new_nonce = derive_nonce(keys.kt,
                           (not is_forward), tweak, nonce)

    # use the value of S to encrypt the body
    #   C_{I+1} = Decrypt(Kf_I,N_{I+1},C_I)
    # or
    #   C_I = Encrypt(Kb_I,N_I,C_{I+1})

    new_body = xor(body, stream(keys.k, new_nonce, len(body)))
    #print(" relay_crypt {} {} {} -> {} {}".format(
    #    is_forward, body, nonce, new_body, new_nonce))

    return new_body, new_nonce

def origin_crypt(keys, state, body, nonce, is_forward=True):
    """
       Compute the (forward or reverse) encryption of a body and nonce,
       as performed at the origin.
    """
    #    C_I = Encrypt(Kf_I,N_{I+1},C_{I+1})
    # or
    #    C_{I+1} = Decrypt(Kb_I,N_I,C_I)
    new_body = xor(body, stream(keys.k, nonce, len(body)))

    #    T_I = Digest(Khf_I,T'_I||C_I)
    # or
    #    T_I = Digest(Khb_I,T'_I||C_{I+1})
    # As before, note that + means concatenation.
    tweak = digestfn(keys.kh, state.tprime + new_body)

    #   T'_I = T_I
    state.tprime = tweak

    #   N_{n+1} = T_{n+1} ^ E(Ktf_n,T_{n+1} ^ 0)
    # or
    #   N_{I+1} = T_I ^ D(Ktb_I,T_I ^ N_I)
    new_nonce = derive_nonce(keys.kt, is_forward, tweak, nonce)

    return new_body, new_nonce

def derive_one_set_of_keys(kdf):
    """
       Return a new set of keys and a new state, based on a KDF object's
       output.  If with_siv is true, include SIV keys.
    """
    k = kdf.get(STREAM_KEY_LEN)
    kh = kdf.get(DIG_KEY_LEN)
    kt = kdf.get(BLOCK_KEY_LEN)

    keys = LayerKeys(k, kh, kt)
    return (keys, LayerState(zeros(DIGEST_LEN), zeros(DIGEST_LEN)))

def derive_keys(secret_input):
    """
     Derive a forward and reverse set of keys and states; return a tuple of
     ((forwardKeys, forwardState), (backKeys, backState))
    """
    kdf_state = KDF(secret_input)
    forward = derive_one_set_of_keys(kdf_state)
    back = derive_one_set_of_keys(kdf_state)
    return forward, back

class Relay(object):
    """
       Implement the crypto to be performed at a relay.
    """
    def __init__(self, secret_input):
        """
           Initialize the relay's keys and state from a given ntor result.
        """
        # Note that I am assuming that there are separate T' values
        # in each direction.
        ((self.fKeys, self.fState),
         (self.bKeys, self.bState)) = derive_keys(secret_input)

    def relay_forward(self, payload):
        """
           The relay has just receive a forward (outbound) payload of
           PAYLOAD_LEN bytes.  Decrypt it and see if we recognize it.

           If we recognize it, return (True, data), where data is the
           padded data from the payload.

           If we do not recognize it, return (False, nextpayload),
           where nextpayload is what we should send to the next hop.
        """
        assert len(payload) == PAYLOAD_LEN
        data, nonce = payload[:-TAG_LEN], payload[-TAG_LEN:]
        data, nonce = relay_crypt(self.fKeys, self.fState, data, nonce,
                                 is_forward=True)

        # T_(N+1) = Digest(Khf_n,T'_{n+1}||C_{n+1})
        tRecognized = digestfn(self.fKeys.kh_siv,
                               self.fState.tprime + data)

        # Tag = T_{n+1} ^ D(Ktf_n,T_{n+1} ^ N_{n+1})
        tag = derive_nonce(self.fKeys.kt_siv, False, tRecognized, nonce)

        if siv == zeros(TAG_LEN):
            # T_siv' = T_(N+1)
            self.fState.siv_tweak = tRecognized
            return True, data
        else:
            return False, data + nonce

    def relay_backward(self, payload):
        """
           The relay has just received a backward (inbound) payload
           of PAYLOAD_LEN bytes.  Encrypt it and return the payload
           that we should send towards the origin.
        """
        assert len(payload) == PAYLOAD_LEN
        data, nonce = payload[:-TAG_LEN], payload[-TAG_LEN:]
        data, nonce = relay_crypt(self.bKeys, self.bState, data, nonce,
                                 is_forward=False)
        return data + nonce

    def originate_ingoing(self, data):
        """
           The relay wants to originate a cell whose payload contents are
           "data". Return the payload that we should send towards the
           origin.
        """
        assert len(data) <= (PAYLOAD_LEN - TAG_LEN)
        # Pad the data with 0 bytes, and create a 0-valued nonce.
        payload = zpad(data, PAYLOAD_LEN)
        return self.relay_backward(payload)


class Origin(object):
    """
       Implement the crypto to be performed at the origin.
    """
    def __init__(self):
        # Initialize empty lists of keys and states.
        self.fKeys = []
        self.bKeys = []
        self.fStates = []
        self.bStates = []

    def add_hop(self, secret_input):
        """
           Add a single hop to the circuit, deriving the shared keys
           from secret_input.
        """
        ((f,fs), (b,bs)) = derive_keys(secret_input)
        self.fKeys.append(f)
        self.bKeys.append(b)
        self.fStates.append(fs)
        self.bStates.append(bs)

    def originate_outgoing(self, data, target_hop=None):
        """
           Send a cell with content "data" outbound to the
           target_hop-numbered hop (zero-indexed).  If target_hop is
           None, choose the last hop.

           Return the bytes that should be sent to the first hop.
        """
        if target_hop == None:
            target_hop = len(self.fKeys)-1

        data = zpad(data, PAYLOAD_LEN - TAG_LEN)

        oldtweak = self.fStates[target_hop].tprime
        # T_{n+1} = Digest(Khf_n, T'_{n} || C_{n+1})
        tweak = digestfn(self.fKeys[target_hop].kh, oldtweak + data)
        # T'_{n+1} = T_{n+1}
        self.fStates[target_hop].tprime = tweak

        # N_{n+1} = T_{n+1} ^ E(Ktf_n,T_{n+1} ^ 0)
        nonce = derive_nonce(self.fKeys[target_hop].kt,
                             True,
                             tweak,
                             zeros(TAG_LEN))

        for hopnum in range(target_hop, -1, -1):
            fKeys = self.fKeys[hopnum]
            fState = self.fStates[hopnum]
            data, nonce = origin_crypt(fKeys, fState, data, nonce, True)

        return data + nonce

    def receive_cell(self, payload):
        """
           Handle an inbound cell.  If we recognize the cell, return a tuple
           of the cell's data, and the hop that originated the data
           (zero-indexed).  Otherwise return a tuple of None, -1.
        """
        assert len(payload) == PAYLOAD_LEN
        data, nonce = payload[:-TAG_LEN], payload[-TAG_LEN:]
        for hopnum in range(0, len(self.fKeys)):
            bKeys = self.bKeys[hopnum]
            bState = self.bStates[hopnum]

            data, nonce = origin_crypt(bKeys, bState, data, nonce, False)

            if nonce == zeros(TAG_LEN):
                # recognized!
                return data, hopnum

        # not recognized.
        return None, -1

# ========================================
# This part is ugly and bad.  The PyCrypto library doesn't give us a
# reasonable instantiation of AES_CTR with IV, or of HKDF, or of GHASH.

# We will fake a stream cipher, a bogus KDF, and a bogus hash.

# We'll use this for a fake KDF and fake GHASH
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Counter



def digestfn(key, value):
    # This is not ghash. XXXXX
    return SHA256.new(key + value + key).digest()[:DIGEST_LEN]

def block_crypt(key, value, encrypt):
    aes = AES.new(key, AES.MODE_ECB)
    if encrypt:
        result = aes.encrypt(value)
    else:
        result = aes.decrypt(value)
    return result

def stream(key, iv, length):
    ctr = Counter.new(16, prefix=iv[:14]) # not how we should do this.
    aes = AES.new(key, AES.MODE_CTR, counter = ctr)
    return aes.encrypt(b"\0"*length)

def kdf(secret_input, length):
    result = b""
    n = 1
    while len(result) < length:
        d = SHA256.new(secret_input * n).digest()
        result += d
        n += 1
    return result[:length]

class KDF(object):
    def __init__(self, secret_input, output_len_max=1024):
        self.values = kdf(secret_input, output_len_max)

    def get(self, nBytes):
        assert len(self.values) >= nBytes
        result = self.values[:nBytes]
        self.values = self.values[nBytes:]
        return result


# ========================================
# Let's try this out!

shared_secret_1 = b"We can use any bytes"
shared_secret_2 = b"that we want here and"
shared_secret_3 = b"it will be okay."

origin = Origin()
origin.add_hop(shared_secret_1)
origin.add_hop(shared_secret_2)
origin.add_hop(shared_secret_3)

relays = list()
relays.append(Relay(shared_secret_1))
relays.append(Relay(shared_secret_2))
relays.append(Relay(shared_secret_3))

# send an outbound cell to the last hop
cell = origin.originate_outgoing(b"hello world")
rec, cell = relays[0].relay_forward(cell)
assert not rec
rec, cell = relays[1].relay_forward(cell)
assert not rec
rec, cell = relays[2].relay_forward(cell)
assert rec
assert cell == zpad(b"hello world", PAYLOAD_LEN-TAG_LEN)

# Send an inbound cell from the second-to-last-hop.
cell = relays[1].originate_ingoing(b"Hello World!")
cell = relays[0].relay_backward(cell)
body, n = origin.receive_cell(cell)
assert n == 1
assert body == zpad(b"Hello World!", PAYLOAD_LEN - TAG_LEN)


## Now send a second cell in each direction
cell = origin.originate_outgoing(b"Thank you, Tomer, Marc, Orr, and Atul!")
rec, cell = relays[0].relay_forward(cell)
assert not rec
rec, cell = relays[1].relay_forward(cell)
assert not rec
rec, cell = relays[2].relay_forward(cell)
assert rec
assert cell == zpad(b"Thank you, Tomer, Marc, Orr, and Atul!",
                    PAYLOAD_LEN-TAG_LEN)

cell = relays[2].originate_ingoing(b"Onward and upward")
cell = relays[1].relay_backward(cell)
cell = relays[0].relay_backward(cell)
body, n = origin.receive_cell(cell)
assert n == 2
assert body == zpad(b"Onward and upward", PAYLOAD_LEN - TAG_LEN)
