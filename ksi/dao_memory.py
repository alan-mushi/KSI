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
        """
        In json this looks like:
        {
            "org.ksi.client1": {
                "2016-02-18T21:24:56.082991": {
                    b'AAAA': "<sig in base64>",
                    b'BBBB': "<sig in base64>",
                    ...
                },
                "2016-03-21T23:54:50.181911": {
                    b'AAAA': "<sig in base64>"
                }, ...
            },
            "org.ksi.client2": { /* no signatures yet */ },
            ...
        }
        """
        s_id_c = str(resp.ID_C)

        if s_id_c not in self.signed:
            self.signed[s_id_c] = {}

        if resp.t.isoformat() not in self.signed[s_id_c]:
            self.signed[s_id_c][resp.t.isoformat()] = {}

        self.signed[s_id_c][resp.t.isoformat()][msg] = resp.signature
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

    def publish_certificate(self, cert: Certificate) -> bool:
        self.client_certificates[str(cert.id_client)] = cert
        return True

    def publish_signature(self, sig: Signature) -> bool:
        self.signatures[sig.S_t.x] = sig
        return True


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
