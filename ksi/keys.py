from os import urandom
from ksi.hash import Hash

class Keys:
    """
    Keys are the equivalent of z_i in KSI
    """
    @staticmethod
    def genKeys(l=2**16, seed=b'', seedSize=130):
        """
        Generate the z_i values.
        :param l: The number of keys to generate for the Merkle tree (e.g. [z_1...z_l])
        :param seed: The seed, mainly for testing purposes, s_l = hash(seed)
        :param seedSize: The size of the seed to generate (if seed is not supplied)
        :return: The list of keys in correct order: z_0 is at index 0, z_1 at index 1...
        """
        assert l >= 2

        if not seed:
            seed = urandom(seedSize)

        keys = []
        keys.insert(0, Hash.factory(data=bytes(seed)).digest())

        for i in range(1, l+1):
            keys.insert(0, Hash.factory(data=keys[0]).digest())

        return keys
