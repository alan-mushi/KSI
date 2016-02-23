from pymongo import MongoClient
from os import getenv
import pickle

from ksi.dao import DAOFactory, DAOServer, DAOClient
from ksi.ksi_messages import TimestampResponse, bytes_to_base64_str
from ksi.identifier import Identifier
from ksi.certificate import Certificate
from ksi.signverify import Signature


DAO_MONGO_HOST = getenv('KSI_DAO_MONGO_HOST', '127.0.0.1')
DAO_MONGO_PORT = int(getenv('KSI_DAO_MONGO_PORT', '27017'))
DAO_MONGO_CLIENTS_DB = getenv('KSI_DAO_MONGO_CLIENTS_DB', 'clients_db')
DAO_MONGO_SERVER_DB = getenv('KSI_DAO_MONGO_SERVER_DB', 'server_db')
DAO_MONGO_SERVER_DB_COL = getenv('KSI_DAO_MONGO_SERVER_DB_COL', 'signed_requests')
DAO_MONGO_CERTS_DB = getenv('KSI_DAO_MONGO_CERTS_DB', 'clients_certs_db')
DAO_MONGO_CERTS_DB_COL = getenv('KSI_DAO_MONGO_CERTS_DB_COL', 'certificates')
DAO_MONGO_SIGNATURES_DB = getenv('KSI_DAO_MONGO_SIGNATURES_DB', 'signatures_db')


class DAOMongoServer(DAOServer):
    def __init__(self, ):
        super().__init__()
        client = MongoClient(host=DAO_MONGO_HOST, port=DAO_MONGO_PORT)
        self.signed = client[DAO_MONGO_SERVER_DB][DAO_MONGO_SERVER_DB_COL]
        self.client_certificates = client[DAO_MONGO_CERTS_DB][DAO_MONGO_CERTS_DB_COL]

    def publish_signed_request(self, msg: bytes, resp: TimestampResponse) -> bool:
        """
        In json it looks like:
        {
            "org.ksi.client1": {
                "2016-02-18T21:24:56.082991": {
                    base64(b'AAAA'): "<sig in base64>",
                    base64(b'BBBB'): "<sig in base64>",
                    ...
                },
                "2016-03-21T23:54:50.181911": {
                    base64(b'AAAA'): "<sig in base64>"
                }, ...
            },
            "org.ksi.client2": { /* no signatures yet */ },
            ...
        }
        """
        s_id_c = str(resp.ID_C).replace('.', '#')
        doc = {s_id_c: {resp.t.isoformat(): {bytes_to_base64_str(msg): resp.signature}}}

        return self.signed.insert_one(doc).acknowledged

    def get_user_certificate(self, id_client: Identifier) -> Certificate:
        rec = self.client_certificates.find_one({'ID_C': str(id_client).replace('.', '#')})
        cert = Certificate(Identifier(rec['ID_C'].split('#')[-1]), rec['z_0'], rec['r'],
                           rec['t_0'], Identifier(rec['ID_S'].split('#')[-1]), rec['l'])

        return cert

    def get_signed_requests(self):
        return self.signed.find(projection={'_id': 0})


class DAOMongoClient(DAOClient):
    def __init__(self, ):
        super().__init__()
        client = MongoClient(host=DAO_MONGO_HOST, port=DAO_MONGO_PORT)
        self.signatures = client[DAO_MONGO_SIGNATURES_DB]
        self.client_certificates = client[DAO_MONGO_CERTS_DB][DAO_MONGO_CERTS_DB_COL]

    def publish_certificate(self, cert: Certificate) -> bool:
        cert_exist_in_db = self.client_certificates.find_one({'z_0': cert.z_0})

        if cert_exist_in_db:
            return False

        doc = {'ID_C': str(cert.id_client).replace('.', '#'),
               'ID_S': str(cert.id_server).replace('.', '#'),
               'z_0': cert.z_0,
               'r': cert.r,
               't_0': cert.t_0,
               'l': cert.l}

        return self.client_certificates.insert_one(doc).acknowledged

    def publish_signature(self, sig: Signature) -> bool:
        doc = {'ID_C': str(sig.ID_C).replace('.', '#'),
               'i': sig.i,
               'z_i': sig.z_i,
               'message': sig.message,
               'S_t': pickle.dumps(sig.S_t),
               'c_i': pickle.dumps(sig.c_i)}

        return self.signatures[str(sig.ID_C).split('.')[-1]].insert_one(doc).acknowledged


class DAOMongoFactory(DAOFactory):
    dao_client = None
    dao_server = None

    @staticmethod
    def get_client() -> DAOClient:
        if not DAOMongoFactory.dao_client:
            DAOMongoFactory.dao_client = DAOMongoClient()

        return DAOMongoFactory.dao_client

    @staticmethod
    def get_server() -> DAOServer:
        if not DAOMongoFactory.dao_server:
            DAOMongoFactory.dao_server = DAOMongoServer()

        return DAOMongoFactory.dao_server


def clean_databases():
    client = MongoClient(host=DAO_MONGO_HOST, port=DAO_MONGO_PORT)
    l = client.database_names()

    if DAO_MONGO_SERVER_DB in l:
        client.drop_database(DAO_MONGO_SERVER_DB)
    if DAO_MONGO_CERTS_DB in l:
        client.drop_database(DAO_MONGO_CERTS_DB)
    if DAO_MONGO_SIGNATURES_DB in l:
        client.drop_database(DAO_MONGO_SIGNATURES_DB)

    client.close()
