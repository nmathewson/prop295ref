"""Hello!

  This is an attempt to instantiate a version of the latest draft of
  proposal 295 in Python.  I usually find that the best way to see if
  I understand something is by implementing it, so here we go.

  Here are the changes I made:
    - I used SHAKE-256 for a KDF.

    - I used AES-256 instead of AES-128.

    - There are two instances of each T' value -- one for each
      direction. I think this is the intention of the original
      proposal.

    - Since cells can be sent to any circuit on the relay, I replaced
      the idea of T'_{n+1} with Ta'_{n}.  Every relay has to have one,
      not just the last relay.

    - Similarly, the assignment for T'_n_auth needs to be conditional,
      I think.

    - I dropped the "Recognized" field entirely.

  To run this:

    - You will need the PyCryptodome python package, installed as
      "Cryptodome".  (Regular pycrypto doesn't provide ghash or a
      reasonable counter mode.)

"""

from consts import *
from util import *
from aesgcm import *
from kdf import *

class LayerKeys(object):
    """Stores one half the keys for a given layer.  The origin shares two
       of these with each hop in its circuit, one for each direction.

       These keys are immutable over the lifetime of a circuit.

         kt -- a block cipher key used for tweaked encryption of nonce.
         kh -- a hash key used for ghash.
         k -- a stream cipher key used for AES-CTR.
    """
    @staticmethod
    def from_kdf(kdf):
        k = kdf.get(STREAM_KEY_LEN)
        kh = kdf.get(DIG_KEY_LEN)
        kt = kdf.get(BLOCK_KEY_LEN)
        return LayerKeys(k, kh, kt)

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

       The origin also shares a separate LayerState with each hop that
       needs to process authentication to see whether a cell is
       intended for it.

       tprime -- a current tweak value, corresponding to T' in prop295.
    """
    @staticmethod
    def new():
        return LayerState(zeros(BLOCK_LEN))

    def __init__(self, initial_tprime):
        assert len(initial_tprime) == BLOCK_LEN
        self.tprime = initial_tprime

def tweaked_encrypt(key, tweak, nonce):
    """Compute T xor E(key, T xor N), which comes up a lot."""
    return xor(tweak,
               block_encrypt(key, xor(tweak, nonce)))

def tweaked_decrypt(key, tweak, nonce):
    """Compute T xor D(key, T xor N), which comes up a lot."""
    return xor(tweak,
               block_decrypt(key, xor(tweak, nonce)))

def outbound_make_auth(keys, state, m):
    """
       Compute the authentiation for an outbound message.

          The OP prepares the authentication part of the message:

                C_{n+1} = M
                T_{n+1} = Digest(Khf_n,T'_{n+1}||C_{n+1})
                N_{n+1} = T_{n+1} ^ E(Ktf_n,T_{n+1} ^ 0)
                T'_{n+1} = T_{n+1}
    """
    c = m
    t = digest(keys.kh, state.tprime + c)
    n = tweaked_encrypt(keys.kt, t, zeros(BLOCK_LEN))
    state.tprime = t
    # Return the ciphertext-nonce pair.
    return c,n

def outbound_layer_encrypt(keys, state, c, n):
    """
       Perform a single layer of outbound onion enryption on a ciphertext
       and a nonce. Return the ciphertext-nonce pair.

                        C_I = Encrypt(Kf_I,N_{I+1},C_{I+1})
                        T_I = Digest(Khf_I,T'_I||C_I)
                        N_I = T_I ^ E(Ktf_I,T_I ^ N_{I+1})
                        T'_I = T_I
    """
    c = stream_encrypt(keys.k, n, c)
    t = digest(keys.kh, state.tprime + c)
    n = tweaked_encrypt(keys.kt, t, n)
    state.tprime = t
    return c,n

def recognized_at_relay(keys, state, c, n):
    """
       Check the tag on the message-tag pair to see whether it is intended
       for this hop.  Return True if so, and False otherwise.

                T_{n+1} = Digest(Khf_n,T'_{n+1}||C_{n+1})
                Tag = T_{n+1} ^ D(Ktf_n,T_{n+1} ^ N_{n+1})
                T'_{n+1} = T_{n+1}

                The message is authenticated (i.e., M = C_{n+1}) if
                and only if Tag = 0
    """
    t = digest(keys.kh, state.tprime + c)
    tag = tweaked_decrypt(keys.kt, t, n)
    if tag == zeros(TAG_LEN):
        # SPEC NOTE: I believe this assignment has to be conditional?
        # It seems to be unconditional in the proposal.
        state.tprime = t
        return True
    else:
        return False

def outbound_relay_decrypt(keys, state, c, n):
    """
                T_I = Digest(Khf_I,T'_I||C_I)
                N_{I+1} = T_I ^ D(Ktf_I,T_I ^ N_I)
                C_{I+1} = Decrypt(Kf_I,N_{I+1},C_I)
                T'_I = T_I
    """
    t = digest(keys.kh, state.tprime + c)
    n = tweaked_decrypt(keys.kt, t, n)
    c = stream_decrypt(keys.k, n, c)
    state.tprime = t
    return c, n

def inbound_make_auth(m):
    """
       Convert a message to a ciphertext-nonce pair for inbound transmission.

       C_{n+1} = M and N_{n+1}=0
    """
    return m, zeros(16)

def inbound_relay_encrypt(keys, state, c, n):
    """
       Handle a relay's inbound encryption.


                T_I = Digest(Khb_I,T'_I||C_{I+1})
                N_I = T_I ^ E(Ktb_I,T_I ^ N_{I+1})
                C_I = Encrypt(Kb_I,N_I,C_{I+1})
                T'_I = T_I
    """
    t = digest(keys.kh, state.tprime + c)
    n = tweaked_encrypt(keys.kt, t, n)
    c = stream_encrypt(keys.k, n, c)
    state.tprime = t
    return c, n

def inbound_layer_decrypt(keys, state, c, n):
    """
       At the origin: undo a single layer of inbound encryption.

              For I=1...n, where n is the end node on the circuit:
                        C_{I+1} = Decrypt(Kb_I,N_I,C_I)
                        T_I = Digest(Khb_I,T'_I||C_{I+1})
                        N_{I+1} = T_I ^ D(Ktb_I,T_I ^ N_I)
                        T'_I = T_I
    """
    c = stream_decrypt(keys.k, n, c)
    t = digest(keys.kh, state.tprime + c)
    n = tweaked_decrypt(keys.kt, t, n)
    state.tprime = t
    return c, n

def pack(c,n):
    """Convert a ciphertext-nonce pair into a relay body."""
    assert len(c) == PAYLOAD_LEN - BLOCK_LEN
    assert len(n) == BLOCK_LEN
    return c + n

def unpack(body):
    """Convert a relay body into a ciphertext-nonce pair."""
    assert len(body) == PAYLOAD_LEN
    return body[:-BLOCK_LEN], body[-BLOCK_LEN:]

class Relay:
    """
       Simulate a relay using the functions above.
    """
    def __init__(self, shared_secret):
        kdf = KDF(shared_secret)
        self.fKeys = LayerKeys.from_kdf(kdf)
        self.fState = LayerState.new()
        self.bKeys = LayerKeys.from_kdf(kdf)
        self.bState = LayerState.new()

        self.authState = LayerState.new()

    def forward(self, msg):
        """Simulate handling a cell in the outbound direction. If the
           cell is for us, return True and its plaintext.  Otherwise
           return False and the cell as we should forward it to the next step.
        """
        c, n = unpack(msg)
        c, n = outbound_relay_decrypt(self.fKeys, self.fState, c, n)
        # SPEC_NOTE: Note that we're using authState here, and not
        # the "fState" of the next relay in sequence.
        if recognized_at_relay(self.fKeys, self.authState, c, n):
            return True, c
        else:
            return False, pack(c,n)

    def reverse(self, msg):
        """Simulate handling a cell in the inbound direction."""
        c, n = unpack(msg)
        c, n = inbound_relay_encrypt(self.bKeys, self.bState, c, n)
        return pack(c, n)

    def originate(self, msg):
        """Take a plaintext, message, pad it, and add a tag."""
        c = zpad(msg, MAX_MSG_LEN)
        c, n = inbound_make_auth(c)
        return pack(c, n)

class Client:
    """
       Simulate a client's behavior on the network.
    """
    def __init__(self, shared_secrets):
        self.fKeys = list()
        self.bKeys = list()
        self.fState = list()
        self.bState = list()
        self.authState = list()
        self.nHops = 0

        for ss in shared_secrets:
            kdf = KDF(ss)
            self.fKeys.append(LayerKeys.from_kdf(kdf))
            self.bKeys.append(LayerKeys.from_kdf(kdf))
            self.fState.append(LayerState.new())
            self.bState.append(LayerState.new())
            self.authState.append(LayerState.new())
            self.nHops += 1

    def send_msg(self, msg, target):
        """Encrypt 'msg' so that it will be delivered to 'target', where
           'target' is the 0-indexed position of the intended relay.
        """
        assert 0 <= target < self.nHops

        m = zpad(msg, MAX_MSG_LEN)
        c, n = outbound_make_auth(self.fKeys[target], self.authState[target], m)

        for i in range(target, -1, -1):
            c, n = outbound_layer_encrypt(self.fKeys[i], self.fState[i], c, n)

        return pack(c, n)

    def recv_msg(self, msg):
        """Handle an incoming message. If we recognize it, return a two-tuple
           of the originating relay's position and the decrypted message.
           If not, return -1 and an empty string.
        """

        c, n = unpack(msg)
        for i in range(0, self.nHops):
            c, n = inbound_layer_decrypt(self.bKeys[i], self.bState[i], c, n)
            if n == zeros(TAG_LEN):
                return i, c

        return -1, b""

# =========================================================================

class Circuit:
    def __init__(self, secrets):
        self.relays = list()
        for ss in secrets:
            self.relays.append(Relay(ss))

    def outbound(self, msg):
        for pos in range(len(self.relays)):
            recognized, msg = self.relays[pos].forward(msg)
            if recognized:
                return pos, msg
        return -1, msg

    def inbound(self, msg, from_relay):
        msg = self.relays[from_relay].originate(msg)

        for pos in range(from_relay, -1, -1):
            msg = self.relays[pos].reverse(msg)

        return msg

# ============================================================

EX_SECRETS = [ b"abcdef", b"ghijkl", b"mnopqr" ]
client = Client(EX_SECRETS)
circ = Circuit(EX_SECRETS)

m1 = client.send_msg(b"hello", 1)
pos, result = circ.outbound(m1)
assert pos == 1
assert result == zpad(b"hello", MAX_MSG_LEN)

m2 = client.send_msg(b"hello", 1)
assert m2 != m1
pos, result = circ.outbound(m2)
assert pos == 1
assert result == zpad(b"hello", MAX_MSG_LEN)

m3 = client.send_msg(b"world", 2)
pos, result = circ.outbound(m3)
assert pos == 2
assert result == zpad(b"world", MAX_MSG_LEN)

m4 = client.send_msg(b"again", 1)
pos, result = circ.outbound(m4)
assert pos == 1
assert result == zpad(b"again", MAX_MSG_LEN)

m5 = circ.inbound(b"prop295", 2)
pos, result = client.recv_msg(m5)
assert pos == 2
assert result == zpad(b"prop295", MAX_MSG_LEN)

m6 = circ.inbound(b"now is the time for all galois counters", 2)
pos, result = client.recv_msg(m6)
assert pos == 2
assert result == zpad(b"now is the time for all galois counters", MAX_MSG_LEN)


