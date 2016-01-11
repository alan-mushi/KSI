from unittest import TestCase
from ksi.hash import *


class TestHash(TestCase):
    def test_hash_factory(self):
        # SHA-3 (256) test
        sha3 = hash_factory('sha3_256')
        assert (sha3.digest_size == 32)
        assert (sha3.name == 'sha3_256')

        # SHA-1 test
        sha1 = hash_factory('sha1', b'ABCD')
        assert (sha1.digest_size == 20)
        assert (sha1.name == 'sha1')
        assert (sha1.hexdigest() == 'fb2f85c88567f3c8ce9b799c7c54642d0c7b41f6')
        sha1.update(b'ABCD')
        assert (sha1.hexdigest() == '2766daad2aa111d05a46bfbe203c6ae9ee28ea3d')
