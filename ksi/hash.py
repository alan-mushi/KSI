import hashlib
from ksi import HASH_ALGO

if HASH_ALGO.startswith("sha3"):
    import sha3


def hash_factory(alg_name=HASH_ALGO, data=b''):
    """
    Return a hash object initialized with data (if present).
    :param alg_name: Hash algorithm name (e.g. sha1, sha3...), must be available in hashlib/sha3 modules.
    :param data: Initialize the hash object with data.
    :return: A hash object.
    """
    assert isinstance(data, bytes) or isinstance(data, bytearray)
    assert isinstance(alg_name, str)

    return hashlib.new(alg_name, data)
