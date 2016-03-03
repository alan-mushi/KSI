import logging
from datetime import datetime, timedelta

from ksi.identifier import Identifier
from ksi.ksi_messages import TimestampRequest, TimestampResponse, KSIErrorCodes
from ksi.signverify import SignVerify, SIGN_KEY_FORMAT, Signature
from ksi.dao import DAOServer
from ksi.bench_decorator import benchmark_decorator


class KSIServer:
    """
    The KSI server.
    It receive, check and sign time stamping requests.
    User certificates are kept in a dict for the moment (on the long term they should be kept in a database).
    A dict of all signed requests is kept (self.signed) as a dict indexed with the signed message and with the signature
    as value.
    """

    def __init__(self, ID_S: Identifier, dao: DAOServer, filename_private_key: str="output/private_key."+SIGN_KEY_FORMAT):
        """
        Instantiate a server object.
        :param ID_S: The server's identifier
        :type ID_S: Identifier
        :param filename_private_key: The file containing the server's private key (used to sign)
        :type filename_private_key: str
        :param dao: DAO for the server
        :type dao: DAOServer
        """
        assert isinstance(ID_S, Identifier) and isinstance(dao, DAOServer)
        assert isinstance(filename_private_key, str)

        self.ID_S = ID_S
        self.dao = dao
        self.signer = SignVerify()
        self.logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        try:
            self.signer.import_private_keys(filename_private_key)
            logging.debug("Using private key in file '{}'".format(filename_private_key))
        except FileNotFoundError:
            self.logger.error("%s does not exist, generating and exporting keys", filename_private_key)
            self.signer.generate_keys()
            filename_public_key = filename_private_key.replace("private", "public", 1)
            self.signer.export_keys(filename_public_key, filename_private_key)

    @benchmark_decorator
    def get_timestamp_response(self, request: TimestampRequest, callback) -> Signature:
        """
        Send a timestamp response for a given request, check if the fields of TimestampRequest object are valid.
        :param request: The request to answer to
        :type request: TimestampRequest
        :param callback: The function to callback once the TimestampResponse is computed.
            This callback have the following signature: callback(response: TimestampResponse) -> Signature
        :return: The Signature object returned by the callback
        :rtype: Signature
        """
        assert isinstance(request, TimestampRequest)

        self.logger.info("Received timestamp request: %s", str(request))
        t = datetime.utcnow().replace(microsecond=0)  # We take the time at the reception of the request
        status_code = self.__client_certificate_is_valid__(request.ID_C, t)
        response = TimestampResponse(request.x, self.ID_S, request.ID_C, t, status_code)

        if status_code is KSIErrorCodes.NO_ERROR:
            msg, response = self.signer.sign(response)
            assert self.dao.publish_signed_request(msg, response)

        self.logger.info("Responding with St: %s", str(response))

        return callback(response)

    @benchmark_decorator
    def __client_certificate_is_valid__(self, ID_C: Identifier, current_time: datetime) -> KSIErrorCodes:
        """
        Check if the client identified by ID_C have a valid certificate.
        :param ID_C: The client identifier to match to the server's database of user certificates
        :type ID_C: Identifier
        :param current_time: The current time (at which the time stamping request was received)
        :type current_time: datetime
        :return: KSIErrorCodes.NO_ERROR if the certificate for ID_C is valid, KSIErrorCodes.CERTIFICATE_EXPIRED if the
        client certificate expired or KSIErrorCodes.UNSPECIFIED_ERROR for other unexpected error(s)
        :rtype: KSIErrorCodes
        """
        assert isinstance(ID_C, Identifier) and isinstance(current_time, datetime)

        res = KSIErrorCodes.UNSPECIFIED_ERROR
        cert = None

        try:
            cert = self.dao.get_user_certificate(ID_C)
        except KeyError:
            res = KSIErrorCodes.UNKNOWN_CERTIFICATE

        if cert:
            if cert.id_server == self.ID_S:
                if current_time < cert.t_0:
                    res = KSIErrorCodes.CERTIFICATE_TOO_EARLY
                elif current_time <= cert.t_0 + timedelta(seconds=cert.l):
                    res = KSIErrorCodes.NO_ERROR
                else:
                    res = KSIErrorCodes.CERTIFICATE_EXPIRED

        return res
