import json
from datetime import datetime
from enum import Enum, unique
from base64 import standard_b64encode, standard_b64decode
from dateutil.parser import parse

from ksi.identifier import Identifier
from ksi import IDENTIFIER_BASE_NAME


def bytes_to_base64_str(b: bytes) -> str:
    if not b:
        return "None"

    return str(standard_b64encode(b), encoding="ascii")


class TimestampRequest:
    """
    Convenience object for a timestamp request.

    Notation:
        x = hash(message || z_i)
    """

    def __init__(self, x: bytes, ID_C: Identifier):
        """
        Create an object timestamp request with the provided arguments.
        :param x: The hash of the request
        :type x: bytes
        :param ID_C: The client's identifier
        :type ID_C: Identifier
        """
        assert isinstance(x, bytes) and isinstance(ID_C, Identifier)

        self.x = x
        self.ID_C = ID_C

    def __str__(self) -> str:
        """
        :return: A string representation of the object
        :rtype: str
        """
        return "({x}, {idc})".format(x=self.x.hex(), idc=str(self.ID_C))

    def to_json(self) -> str:
        """
        :return: The JSON string representation of the object
        :rtype: str
        """
        return json.dumps({'x': bytes_to_base64_str(self.x), 'ID_C': str(self.ID_C)})

    @staticmethod
    def from_json(json_obj: dict):
        """
        :param json_obj: JSON representation of a TimestampRequest object
        :type json_obj: dict
        :return: A new TimestampRequest from the json parameter
        :rtype: TimestampRequest
        """
        assert 'x' in json_obj and 'ID_C' in json_obj

        id = json_obj['ID_C']  # type: str
        if id.startswith(IDENTIFIER_BASE_NAME):
            # Removes IDENTIFIER_BASE_NAME from the beginning of the identifier string
            id = id[len(IDENTIFIER_BASE_NAME):]

        return TimestampRequest(standard_b64decode(json_obj['x']), Identifier(id))


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
        if isinstance(self.x, bytes):
            x_str = self.x.hex()
        else:
            x_str = self.x.hexdigest()

        return "(x: {x}, ID_C: {idc})\t=>\t(status_code: {status_code}, ID_S: {ids}, t: {t}, signature: {sig})".format(
            x=x_str,
            idc=str(self.ID_C),
            status_code=str(self.status_code),
            ids=str(self.ID_S),
            t=self.t.isoformat(),
            sig=self.signature)

    def to_json(self) -> str:
        """
        :return: A JSON string representation of the object
        :rtype: str
        """
        sig_str = "None"

        if self.signature:
            sig_str = str(self.signature, encoding="ascii")

        return json.dumps({'status_code': str(self.status_code),
                           'x': bytes_to_base64_str(self.x),
                           'ID_C': str(self.ID_C),
                           'ID_S': str(self.ID_S),
                           't': self.t.isoformat(),
                           'signature': sig_str})

    @staticmethod
    def from_json_dict(json_obj: dict):
        """
        :param json_obj: A JSON representation of the TimestampResponse object
        :type json_obj: dict
        :return: A new TimestampResponse built from the json_obj parameter
        :rtype: TimestampResponse
        """
        assert 'status_code' in json_obj
        assert 'x' in json_obj
        assert 'ID_C' in json_obj
        assert 'ID_S' in json_obj
        assert 't' in json_obj
        assert 'signature' in json_obj

        status_code = KSIErrorCodes[json_obj['status_code']]
        x = standard_b64decode(json_obj['x'])
        ID_C = Identifier(json_obj['ID_C'][len(IDENTIFIER_BASE_NAME):])
        ID_S = Identifier(json_obj['ID_S'][len(IDENTIFIER_BASE_NAME):])
        t = parse(json_obj['t'])

        if json_obj['signature'] == "None":
            signature = None
        else:
            signature = bytes(json_obj['signature'], encoding="ascii")

        res = TimestampResponse(x, ID_S, ID_C, t, status_code)
        res.signature = signature

        return res
