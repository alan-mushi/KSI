import hashlib, sha3
from . import HASH_ALGO


class Hash:
    @staticmethod
    def factory(algName=None, data=b''):
        """
        Return a hash object initialized with data (if present).
        :param alg_name: Hash algorithm name (e.g. sha1, sha3...), must be available in hashlib/sha3 modules.
        :param data: Initialize the hash object with data.
        :return: A hash object.
        """
        if not algName:
            algName = HASH_ALGO

        return hashlib.new(algName, data)
