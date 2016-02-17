from ksi.dao import DAOFactory, DAOServer, DAOClient
from ksi.ksi_messages import TimestampResponse
from ksi.identifier import Identifier
from ksi.certificate import Certificate
from ksi.signverify import Signature


class DAOMemoryServer(DAOServer):
    def __init__(self, client_certificates: dict):
        super().__init__()
        self.signed = {}
        self.client_certificates = client_certificates

    def publish_signed_request(self, msg: bytes, resp: TimestampResponse) -> bool:
        self.signed[msg] = resp.signature
        return True

    def get_user_certificate(self, id_client: Identifier) -> Certificate:
        return self.client_certificates[str(id_client)]

    def get_signed_requests(self):
        return dict(self.signed)


class DAOMemoryClient(DAOClient):
    def __init__(self, client_certificates: dict):
        super().__init__()
        self.signatures = {}
        self.client_certificates = client_certificates
        self.msg_to_x = {}

    def publish_certificate(self, cert: Certificate) -> bool:
        self.client_certificates[str(cert.id_client)] = cert
        return True

    def publish_signature(self, x: str, msg: bytes, sig: Signature) -> bool:
        if msg in self.msg_to_x:
            return False

        self.msg_to_x[msg] = x
        self.signatures[x] = sig
        return True

    def get_signature(self, msg: bytes) -> Signature:
        if msg in self.msg_to_x and self.msg_to_x[msg] in self.signatures:
            return self.signatures[self.msg_to_x[msg]]
        else:
            return None


class DAOMemoryFactory(DAOFactory):
    dao_client = None
    dao_server = None
    client_certificates = {}

    @staticmethod
    def get_client() -> DAOClient:
        if not DAOMemoryFactory.dao_client:
            DAOMemoryFactory.dao_client = DAOMemoryClient(DAOMemoryFactory.client_certificates)

        return DAOMemoryFactory.dao_client

    @staticmethod
    def get_server() -> DAOServer:
        if not DAOMemoryFactory.dao_server:
            DAOMemoryFactory.dao_server = DAOMemoryServer(DAOMemoryFactory.client_certificates)

        return DAOMemoryFactory.dao_server
