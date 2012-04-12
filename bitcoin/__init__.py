from _bitcoin import *
from bind import bind, _1, _2, _3

# Turn off libbitcoin output
disable_logging()

class output_point(input_point):
    pass

def data_chunk(strval=""):
    if len(strval) % 2 != 0:
        raise IndexError("bytes representation must be multiple of 2")
    return bytes_from_pretty(strval)

def hash_digest(strval=""):
    if len(strval) != 2 * 32:
        raise indexerror("length of hash_digest representation should be 2 * 32 characters")
    return hash_digest_from_pretty(strval)

def short_hash(strval):
    if len(strval) != 2 * 20:
        raise indexerror("length of short_hash representation should be 2 * 20 characters")
    return short_hash_from_pretty(strval)

class wrapped_callable:

    def __init__(self, strand, handler):
        self.strand = strand
        self.handler = handler

    def __call__(self, *args):
        self.strand.dispatch(bind(self.handler, *args))

class strand(strand_wrapper):

    def wrap(self, handler):
        return wrapped_callable(self, handler)

