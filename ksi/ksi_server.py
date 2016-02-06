import logging
from datetime import datetime, timedelta

from ksi.identifier import Identifier
from ksi.ksi_messages import TimestampRequest, TimestampResponse, KSIErrorCodes
from ksi.signverify import SignVerify, SIGN_KEY_FORMAT
from ksi.certificate import Certificate


class KSIServer:
    """
    The KSI server.
    It receive, check and sign time stamping requests.
    User certificates are kept in a dict for the moment (on the long term they should be kept in a database).
    A dict of all signed requests is kept (self.signed) as a dict indexed with the signed message and with the signature
    as value.
    """

    def __init__(self, ID_S: Identifier, client_certificates: dict={},
                 filename_private_key: str="output/private_key."+SIGN_KEY_FORMAT):
        """
        Instantiate a server object.
        :param ID_S: The server's identifier
        :type ID_S: Identifier
        :param filename_private_key: The file containing the server's private key (used to sign)
        :type filename_private_key: str
        :param client_certificates: A dict of user certificates indexed by their identifier as sting
        :type client_certificates: dict
        """
        assert isinstance(ID_S, Identifier) and isinstance(client_certificates, dict)
        assert isinstance(filename_private_key, str)

        self.ID_S = ID_S
        self.client_certificates = client_certificates
        self.signer = SignVerify()
        self.signed = {}  # type: dict[str, Certificate]

        try:
            self.signer.import_private_keys(filename_private_key)
        except FileNotFoundError:
            logging.error("%s does not exist, generating and exporting keys", filename_private_key)
            self.signer.generate_keys()
            filename_public_key = filename_private_key.replace("private", "public", 1)
            self.signer.export_keys(filename_public_key, filename_private_key)

    def send_request(self, request: TimestampRequest, callback):
        """
        Send a timestamp response for a given request, check if the fields of TimestampRequest object are valid.
        :param request: The request to answer to
        :type request: TimestampRequest
        :param callback: The function to callback once the TimestampResponse is computed.
            This callback have the following signature: callback(response: TimestampResponse)
        """
        assert isinstance(request, TimestampRequest)

        logging.info("Received timestamp request: %s", str(request))
        t = datetime.utcnow()  # We take the time at the reception of the request
        status_code = self.__client_certificate_is_valid__(request.ID_C, t)
        response = TimestampResponse(request.x, self.ID_S, request.ID_C, t, status_code)

        if status_code is KSIErrorCodes.NO_ERROR:
            msg, response = self.signer.sign(response)

            if msg in self.signed:
                logging.FATAL("Signed message is already in the dict of signed messages!")
                raise ValueError("Signed message is already in the dict of signed messages!")
            else:
                self.signed[msg] = response.signature

        logging.info("Responding with St: %s", str(response))
        callback(response)

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
            cert = self.client_certificates[str(ID_C)]  # type: Certificate
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
