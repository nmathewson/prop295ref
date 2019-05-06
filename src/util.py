
__all__ = [ "xor", "zeros", "zpad" ]

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

