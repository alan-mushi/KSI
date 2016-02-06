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


class TestKSIServer(TestCase):
    @classmethod
    def setUpClass(cls):
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
        server = KSIServer(self.id_server, client_certificates={})

        print("AAAAAAAAAA: " + str(len(server.client_certificates)))

        assert len(server.client_certificates) == 0
        assert len(server.signed) == 0
        assert server.signer.key and server.signer.key.has_private() and server.signer.key.publickey()

    def test_2_key_import(self):
        server = KSIServer(self.id_server)
        assert server.signer.key.has_private() and server.signer.key.can_sign()
        server.signer.import_public_keys("output/public_key." + SIGN_KEY_FORMAT)
        assert server.signer.key.publickey()

    def test_3_missing_client_certificate(self):
        server = KSIServer(self.id_server)
        l = 8
        keys = Keys(l=l, seed=b'SEED')
        client = KSIClient(server, keys=keys)

        client.sign(b'AAAA')
        assert len(client.signatures) == 0 and len(server.signed) == 0
        #
        # The successful signature test case is in test_KSIClient.py
        #

    def test_4_client_certificate_too_early(self):
        server = KSIServer(self.id_server)
        l = 8
        keys = Keys(l=l, seed=b'SEED')
        client = KSIClient(server, keys=keys)
        server.client_certificates[str(client.certificate.id_client)] = deepcopy(client.certificate)
        server.client_certificates[str(client.certificate.id_client)].t_0 += timedelta(seconds=100)
        client.sign(b'AAAA')
        assert len(client.signatures) == 0 and len(server.signed) == 0
