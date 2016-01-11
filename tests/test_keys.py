from unittest import TestCase
from ksi.hash import *
from ksi.keys import Keys


class TestKeys(TestCase):
    def test_genKeys(self):
        seed = b'ABCD'

        keys = Keys.gen_keys(2, seed)
        keys2 = Keys.gen_keys(4, seed)

        for i, val in enumerate(keys2):
            print("z_{0:d} = {1:s}".format(i, val.hex()))

        # Check if the two last z_i are equal
        assert keys[-1] == keys2[-1]
        assert keys[-2] == keys2[-2]

        print("\nVerification of the hash chain (first 4 elements):")
        z = {}
        z[4] = hash_factory(data=seed).digest()
        z[3] = hash_factory(data=z[4]).digest()
        z[2] = hash_factory(data=z[3]).digest()
        z[1] = hash_factory(data=z[2]).digest()
        z[0] = hash_factory(data=z[1]).digest()

        for i, _ in enumerate(z):
            assert z[i] == keys2[i]
            print("z_{0:d} == keys2[{0:d}] -> {1:s}".format(i, z[i].hex()))

        print("\nGenerate 2**10 random z_i:")
        rand_keys = Keys.gen_keys(2 ** 16)
        print("z_{0:d} = {1:s}".format(0, rand_keys[0].hex()), end="\t...\t")
        print("z_{0:d} = {1:s}".format(len(rand_keys)-1, rand_keys[-1].hex()))
