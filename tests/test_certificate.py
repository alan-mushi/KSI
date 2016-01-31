from unittest import TestCase
from datetime import datetime

from ksi.certificate import Certificate
from ksi.keys import Keys
from ksi.identifier import Identifier


class TestCertificate(TestCase):
    def test_default(self):
        id_client = Identifier("client")
        id_server = Identifier("server")
        seed = b'\xde\xad\xbe\xef'
        keys = Keys(l=4, seed=seed)
        z0 = keys.keys[0].hash
        r = keys.hash_tree_root.hash
        t0 = datetime.now()

        cert = Certificate(id_client, z0, r, t0, id_server)
        print(cert)

        # There isn't much of testing to be done here as Certificate is a convenience class...
        assert cert is not None
