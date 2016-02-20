from unittest import TestCase

from ksi.ksi_client import KSIClient
from ksi.ksi_server import KSIServer
from ksi.keys import Keys
from ksi.hash import hash_factory
from ksi.dao_mongo import *
from ksi.dao import *


class TestDAOMongo(TestCase):

    @classmethod
    def setUpClass(cls):
        clean_databases()

    def test_all(self):
        dao_factory = factory(DAOMongoFactory)
        server = KSIServer(Identifier('server'), dao_factory.get_server())
        keys = Keys(l=256, seed=b'SEED')
        client = KSIClient(server, dao_factory.get_client(), keys=keys)
        ref_cert = client.certificate

        mongo_cert = server.dao.get_user_certificate(client.certificate.id_client)
        self.assertTrue(ref_cert == mongo_cert)

        ref_msg = hash_factory(data=b'DATA').digest()
        sig = client.sign(ref_msg)
        client.verify(sig, client.certificate, ref_msg)
