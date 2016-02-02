from datetime import datetime

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
        return "({x}, {idc})".format(x=self.x.hexdigest(), idc=str(self.ID_C))


class TimestampResponse:
    """
    Convenience object for a timestamp response (this corresponds to S_t in the LaTeX notation of KSI).
    """

    def __init__(self, x, ID_S: Identifier, ID_C: Identifier, t: datetime, signature: bytes):
        """
        Create an object timestamp response with the provided arguments.
        :param x: The hash of the request
        :param ID_S: The server's identifier
        :type ID_S: Identifier
        :param ID_C: The client's identifier
        :type ID_C: Identifier
        :param t: The time at which the request has been signed
        :type t: datetime
        :param signature: The signature for (x, ID_C)
        """
        assert isinstance(ID_S, Identifier) and isinstance(ID_C, Identifier)
        assert isinstance(t, datetime)

        self.x = x
        self.ID_C = ID_C
        self.ID_S = ID_S
        self.t = t
        self.signature = signature

    def __str__(self) -> str:
        """
        :return: A string representation of the object
        """
        return "(x: {x}, ID_C: {idc})\t=>\t(ID_S: {ids}, t: {t}, signature: {sig})".format(x=self.x.hexdigest(),
                                                                                           idc=str(self.ID_C),
                                                                                           ids=str(self.ID_S),
                                                                                           t=self.t.isoformat(),
                                                                                           sig=str(self.signature))
