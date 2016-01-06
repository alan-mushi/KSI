import hashlib


class Hash:
    @staticmethod
    def factory(alg_name='sha3_256', data=b'', data2=b''):
        """
        Return a hash object initialized with data and data2 (if present).
        :param alg_name: Hash algorithm name (e.g. sha1, sha3...), must be available in hashlib/sha3 modules.
        :param data: Initialize the hash object with data.
        :param data2: Call update(data2) on the created hash object.
        :return: A hash object.
        """
        h = hashlib.new(alg_name, data)

        if h and data2 != b'':
            h.update(data2)

        return h
