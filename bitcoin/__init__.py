from _bitcoin import *
initialize_python()
from bind import bind, _1, _2, _3

class output_point(input_point):
    pass

def data_chunk(strval=""):
    if len(strval) % 2 != 0:
        raise IndexError("bytes representation must be multiple of 2")
    return bytes_from_pretty(strval)

def hash_digest(strval=""):
    if len(strval) != 2 * 32:
        raise IndexError("length of hash_digest representation should be 2 * 32 characters")
    return hash_from_pretty(strval)

def short_hash(strval):
    raise Exception("Unimplemented!")

