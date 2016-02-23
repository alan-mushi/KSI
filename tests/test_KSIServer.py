from unittest import TestCase
from os import remove
from datetime import timedelta
from copy import deepcopy
import logging

from ksi.ksi_server import KSIServer
from ksi.identifier import Identifier
from ksi.ksi_client import KSIClient
from ksi.keys import Keys
from ksi import SIGN_KEY_FORMAT
from ksi.dao import factory
from ksi.dao_memory import DAOMemoryFactory, DAOMemoryServer


class TestKSIServer(TestCase):
    @classmethod
    def setUpClass(cls):
        DAOMemoryFactory.dao_client = None
        DAOMemoryFactory.dao_server = None
        DAOMemoryFactory.client_certificates = {}

        try:
            remove("output/public_key." + SIGN_KEY_FORMAT)
        except FileNotFoundError:
            pass

        try:
            remove("output/private_key." + SIGN_KEY_FORMAT)
        except FileNotFoundError:
            pass

    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        self.id_server = Identifier("server")

    def test_1_key_generation(self):
        dao_factory = factory(DAOMemoryFactory)
        dao_memory_server = dao_factory.get_server()  # type: DAOMemoryServer
        server = KSIServer(self.id_server, dao_memory_server)

        assert len(dao_memory_server.client_certificates) == 0
        assert len(dao_memory_server.signed) == 0
        assert server.signer.key and server.signer.key.has_private() and server.signer.key.publickey()

    def test_2_key_import(self):
        dao_factory = factory(DAOMemoryFactory)
        server = KSIServer(self.id_server, dao_factory.get_server())
        assert server.signer.key.has_private() and server.signer.key.can_sign()
        server.signer.import_public_keys("output/public_key." + SIGN_KEY_FORMAT)
        assert server.signer.key.publickey()

    def test_3_missing_client_certificate(self):
        # This test works because the DAO memory share certificates among the client and server DAO
        dao_factory = factory(DAOMemoryFactory)
        server = KSIServer(self.id_server, dao_factory.get_server())
        l = 8
        keys = Keys(l=l, seed=b'SEED')
        client = KSIClient(server, dao_factory.get_client(), keys=keys)

        client.sign(b'AAAA')
        assert len(dao_factory.get_client().signatures) == 1 and len(dao_factory.get_server().signed) == 1

    def test_4_client_certificate_too_early(self):
        dao_factory = factory(DAOMemoryFactory)
        dao_memory_server = dao_factory.get_server()  # type: DAOMemoryServer
        server = KSIServer(self.id_server, dao_factory.get_server())
        l = 8
        keys = Keys(l=l, seed=b'SEED2')
        client2 = KSIClient(server, dao_factory.get_client(), keys=keys, ID_C_str='client2')
        dao_memory_server.client_certificates[str(client2.certificate.id_client)].t_0 += timedelta(seconds=100)

        with self.assertRaises(ValueError):
            client2.sign(b'AAAA')

        assert len(dao_factory.get_client().signatures) == 1 and len(dao_memory_server.signed) == 1
