import logging
from datetime import datetime

from ksi.identifier import Identifier
from ksi.ksi_messages import TimestampRequest, TimestampResponse


class KSIServer:
    """
    TODO: edit this documentation once finalized.

    A Mock class acting as a server.
    """
    # TODO this is simply a mock class, all the logic is missing!

    def __init__(self, ID_S: Identifier):
        """
        Create a server object.
        :param ID_S: The server's identifier
        :type ID_S: Identifier
        """
        assert isinstance(ID_S, Identifier)

        self.ID_S = ID_S

    def send_request(self, request: TimestampRequest, callback):
        """
        Send a timestamp response for a given request.
        :param request: The request to answer to
        :type request: TimestampRequest
        :param callback: The function to callback once the TimestampResponse is computed.
            This callback should have the following signature: callback(response: TimestampResponse)
        """
        assert isinstance(request, TimestampRequest)

        logging.info("Received timestamp request: %s", str(request))
        response = TimestampResponse(request.x, self.ID_S, request.ID_C, datetime.utcnow(), signature=None)
        logging.info("\tResponding with St: %s", str(response))
        callback(response)
