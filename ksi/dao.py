from ksi.certificate import Certificate
from ksi.signverify import Signature
from ksi.ksi_messages import TimestampResponse
from ksi.identifier import Identifier


class DAOServer:
    def __init__(self):
        """
        Used to instantiate the connection.
        """
        pass

    def publish_signed_request(self, msg: bytes, resp: TimestampResponse) -> bool:
        """
        Publish signed: msg -> S_t.
        :param msg: The message
        :type msg: bytes
        :param resp: The response to publish
        :type resp: TimestampResponse
        :return: True if published, False otherwise
        :rtype: bool
        """
        pass

    def get_user_certificate(self, id_client: Identifier) -> Certificate:
        """
        Get the certificate corresponding to the client's Identifier.
        :param id_client: The client's Identifier
        :type id_client: Identifier
        :return: None if the certificate wasn't found, the certificate otherwise
        :rtype: Certificate
        """
        pass

    def get_signed_requests(self):
        """
        Get the list of signed requests.
        :return: A list of all signed requests
        :rtype: list
        """
        pass


class DAOClient:
    def __init__(self):
        """
        Used to instantiate the connection.
        """
        pass

    def publish_certificate(self, cert: Certificate) -> bool:
        """
        Publish a user's certificate.
        :param cert: The client's certificate to
        :type cert: Certificate
        :return: True if the certificate was correctly published, False otherwise
        :rtype: bool
        """
        pass

    def publish_signature(self, x: str, sig: Signature) -> bool:
        """
        Publish a signature on a document.
        :param x: The "message" associated with the signature
        :type x: str
        :param sig: The signature to publish
        :type sig: Signature
        :return: True if the signature was published, False otherwise
        :rtype: bool
        """
        pass


class DAOFactory:
    @staticmethod
    def get_client():
        pass

    @staticmethod
    def get_server():
        pass


def factory(dao_type: type):

    from ksi.dao_memory import DAOMemoryFactory
    if dao_type.__name__ == DAOMemoryFactory.__name__:
        return DAOMemoryFactory()
