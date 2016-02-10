from datetime import datetime
from enum import Enum, unique
from flask import jsonify
from base64 import standard_b64encode, standard_b64decode
from dateutil.parser import parse

from ksi.identifier import Identifier


class TimestampRequest:
    """
    Convenience object for a timestamp request.

    Notation:
        x = hash(message || z_i)
    """

    def __init__(self, x, ID_C: Identifier):
        """
        Create an object timestamp request with the provided arguments.
        :param x: The hash of the request
        :param ID_C: The client's identifier
        :type ID_C: Identifier
        """
        assert isinstance(ID_C, Identifier)

        self.x = x
        self.ID_C = ID_C

    def __str__(self) -> str:
        """
        :return: A string representation of the object
        """
        x_str = None

        if isinstance(self.x, bytes):
            x_str = self.x
        else:
            x_str = self.x.hexdigest()

        return "({x}, {idc})".format(x=x_str, idc=str(self.ID_C))

    def to_json(self) -> str:
        """
        :return: The JSON string representation of the object
        :rtype: str
        """
        return jsonify({'x': standard_b64encode(self.x), 'ID_C': str(self.ID_C)})

    @staticmethod
    def from_json(json: str):
        """
        :param json: JSON representation of a TimestampRequest object
        :type json: str
        :return: A new TimestampRequest from the json parameter
        :rtype: TimestampRequest
        """
        assert json['x'] and json['ID_C']
        return TimestampRequest(standard_b64decode(json['x']), Identifier(json['ID_C']))


@unique
class KSIErrorCodes(Enum):
    NO_ERROR = 0
    UNKNOWN_CERTIFICATE = 1
    CERTIFICATE_EXPIRED = 2
    CERTIFICATE_TOO_EARLY = 3
    UNSPECIFIED_ERROR = 4

    def __str__(self):
        return self.name


class TimestampResponse:
    """
    Convenience object for a timestamp response (this corresponds to S_t in the LaTeX notation of KSI).
    """

    def __init__(self, x, ID_S: Identifier, ID_C: Identifier, t: datetime, status_code: KSIErrorCodes):
        """
        Create an object timestamp response with the provided arguments.
        The signature is set to None.
        :param x: The hash of the request
        :param ID_S: The server's identifier
        :type ID_S: Identifier
        :param ID_C: The client's identifier
        :type ID_C: Identifier
        :param t: The time at which the request has been signed
        :type t: datetime
        :param status_code: A status code filled by the server to indicate errors or the lack thereof
        :type status_code: KSIErrorCodes
        """
        assert isinstance(ID_S, Identifier) and isinstance(ID_C, Identifier)
        assert isinstance(t, datetime)
        assert isinstance(status_code, KSIErrorCodes)

        self.x = x
        self.ID_C = ID_C
        self.ID_S = ID_S
        self.t = t
        self.signature = None
        self.status_code = status_code

    def __str__(self) -> str:
        """
        :return: A string representation of the object
        :rtype: str
        """
        x_str = None

        if isinstance(self.x, bytes):
            x_str = self.x.hex()
        else:
            x_str = self.x.hexdigest()

        return "(x: {x}, ID_C: {idc})\t=>\t\
                (status_code: {status_code}, ID_S: {ids}, t: {t}, signature: {sig})".format(x=x_str,
                                                                                            idc=str(self.ID_C),
                                                                                            status_code=str(
                                                                                                self.status_code),
                                                                                            ids=str(self.ID_S),
                                                                                            t=self.t.isoformat(),
                                                                                            sig=str(self.signature))

    def to_json(self) -> str:
        """
        :return: A JSON string representation of the object
        :rtype: str
        """
        sig_str = "None"

        if self.signature:
            sig_str = str(self.signature, encoding="ascii")

        return jsonify({'status_code': str(self.status_code),
                        'x': str(standard_b64encode(self.x), encoding="ascii"),
                        'ID_C': str(self.ID_C),
                        'ID_S': str(self.ID_S),
                        't': self.t.isoformat(),
                        'signature': sig_str})

    @staticmethod
    def from_json(json: str):
        """
        :param json: A JSON representation of the TimestampResponse object
        :type json: str
        :return: A new TimestampResponse built from the json parameter
        :rtype: TimestampResponse
        """
        assert json['status_code'] and json['x'] and json['ID_C'] and json['ID_S'] and json['t'] and json['signature']
        status_code = KSIErrorCodes(int(json['status_code']))
        x = standard_b64decode(json['x'])
        ID_C = Identifier(json['ID_C'])
        ID_S = Identifier(json['ID_S'])
        t = parse(json['t'])
        signature = standard_b64decode(json['signature'])

        res = TimestampResponse(x, ID_S, ID_C, t, status_code)
        res.signature = signature

        return res
