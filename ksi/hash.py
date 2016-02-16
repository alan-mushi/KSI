import hashlib
from ksi import HASH_ALGO


def hash_factory(alg_name=HASH_ALGO, data=b''):
    """
    Return a hash object initialized with data (if present).
    Support for Haraka is **experimental**.
    :param alg_name: Hash algorithm name (e.g. sha1, sha3...), must be available in hashlib/sha3 modules
    :param data: Initialize the hash object with data
    :return: A hash object (of unknown type)
    """
    assert isinstance(data, bytes) or isinstance(data, bytearray)
    assert isinstance(alg_name, str)

    if alg_name == "haraka_512_256":
        from ksi.haraka import Haraka512_256
        return Haraka512_256(bytes(data))

    elif alg_name == "haraka_256_256":
        from ksi.haraka import Haraka256_256
        return Haraka256_256(bytes(data))

    elif alg_name.startswith("sha3"):
        import sha3

    return hashlib.new(alg_name, data)
