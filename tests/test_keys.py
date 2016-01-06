from unittest import TestCase
from ksi.keys import Keys
from ksi.hash import Hash


class TestKeys(TestCase):
    def test_genKeys(self):
        seed = b"ABCD"

        keys = Keys.genKeys(2, seed)
        keys2 = Keys.genKeys(4, seed)

        for i, val in enumerate(keys2):
            print("z_{0:d} = {1:s}".format(i, val.hex()))

        # Check if the two last z_i are equal
        assert keys[-1] == keys2[-1]
        assert keys[-2] == keys2[-2]

        print("\nVerification of the hash chain (first 4 elements):")
        z = {}
        z[4] = Hash.factory(data=seed).digest()
        z[3] = Hash.factory(data=z[4]).digest()
        z[2] = Hash.factory(data=z[3]).digest()
        z[1] = Hash.factory(data=z[2]).digest()
        z[0] = Hash.factory(data=z[1]).digest()

        for i, hash in enumerate(z):
            assert z[i] == keys2[i]
            print("z_{0:d} == keys2[{0:d}] -> {1:s}".format(i, z[i].hex()))

        print("\nGenerate 2**10 random z_i:")
        for i, val in enumerate(Keys.genKeys(2**10)):
            print("z_{0:d} = {1:s}".format(i, val.hex()))
