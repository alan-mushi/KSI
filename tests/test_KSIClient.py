from unittest import TestCase
from time import sleep
import graphviz
import logging

from ksi.ksi_client import KSIClient
from ksi.ksi_server import KSIServer
from ksi.identifier import Identifier
from ksi.keys import Keys
from ksi.ksi_messages import KSIErrorCodes
from ksi.dao import factory
from ksi.dao_memory import DAOMemoryFactory, DAOMemoryClient


class TestKSIClient(TestCase):
    @classmethod
    def setUpClass(cls):
        DAOMemoryFactory.dao_client = None
        DAOMemoryFactory.dao_server = None
        DAOMemoryFactory.client_certificates = {}

    def test_sign(self):
        dao_factory = factory(DAOMemoryFactory)
        dao_memory_client = dao_factory.get_client()  # type: DAOMemoryClient

        logging.basicConfig(level=logging.DEBUG)

        server_id = Identifier("server")
        server = KSIServer(server_id, dao_factory.get_server())
        l = 8
        keys = Keys(l=l, seed=b'SEED')
        client = KSIClient(server, dao_memory_client, keys=keys)

        # dao_memory_server.client_certificates[str(client.certificate.id_client)] = client.certificate
        sleep_counter = 2

        sleep(sleep_counter)
        client.sign(b'AAAA')

        # Compute graphviz on the whole merkle graph
        g1 = graphviz.Digraph(name="after sign", directory="./output", format="dot", node_attr={"shape": "box"})
        g1 = keys.hash_tree_root.to_graphviz(g1)
        g1.render()

        # Compute graphviz only the hash chain
        print("Signatures: ")
        for k, v in client.dao.signatures.items(): # type: _sha3.SHA3, Signature
            print("[{k}] = {v}".format(k=k.hexdigest(), v=v))
            assert v.S_t.status_code == KSIErrorCodes.NO_ERROR
            g2 = graphviz.Digraph(name="hash chain", directory="./output", format="dot", node_attr={"shape": "box"})
            g2 = v.c_i.to_graphviz(g2)
            g2.render()

        # +1 for "the sleep before publishing the signature" mechanism
        sleep_counter += 2 + 1
        client.signatures = {}
        sleep(2)
        client.sign(b'BBBB')

        # Compute graphviz on the whole merkle graph
        g3 = graphviz.Digraph(name="after sign 2", directory="./output", format="dot", node_attr={"shape": "box"})
        g3 = keys.hash_tree_root.to_graphviz(g3)
        g3.render()

        # Compute graphviz only the hash chain
        print("Signatures: ")
        for k, v in client.dao.signatures.items(): # type: _sha3.SHA3, Signature
            print("[{k}] = {v}".format(k=k.hexdigest(), v=v))
            g4 = graphviz.Digraph(name="hash chain 2", directory="./output", format="dot", node_attr={"shape": "box"})
            g4 = v.c_i.to_graphviz(g4)
            g4.render()

        sleep(l-sleep_counter-1)

        with self.assertRaises(ValueError):
            client.sign(b'CCC')

    def test_sign_coverage(self):
        dao_factory = factory(DAOMemoryFactory)
        client = KSIClient(KSIServer(Identifier("server"), dao_factory.get_server()), dao_factory.get_client())

    def test_verify(self):
        dao_factory = factory(DAOMemoryFactory)
        client = KSIClient(KSIServer(Identifier("server"), dao_factory.get_server()), dao_factory.get_client())
        message = b'AAAA'
        message2 = b'BBBB'
        message3 = b'CCCC'
        client.verify(message)
        client.verify(message2)
        client.verify(message3)
