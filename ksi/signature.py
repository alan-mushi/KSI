from ksi.ksi_messages import TimestampResponse
from ksi.merkle_tree import Node
from ksi.identifier import Identifier


class Signature:
    """
    Convenience class to hold a signature.
    """

    def __init__(self, ID_C: Identifier, i: int, z_i: bytes, c_i: Node, S_t: TimestampResponse):
        """
        Create a signature object with the provided arguments.
        :param ID_C: The client's identifier
        :type ID_C: Identifier
        :param i: the time offset in the list of z_i
        :type i: int
        :param z_i: The z_i used to compute the hash chain
        :type z_i: bytes
        :param c_i: The hash chain
        :type c_i: Node
        :param S_t: S_t (aka the TimestampResponse object delivered by the server)
        :type S_t: TimestampResponse
        """
        assert isinstance(ID_C, Identifier)
        assert isinstance(i, int)
        assert isinstance(z_i, bytes)
        assert isinstance(c_i, Node)
        assert isinstance(S_t, TimestampResponse)

        self.ID_C = ID_C
        self.i = i
        self.z_i = z_i
        self.c_i = c_i
        self.S_t = S_t

    def __str__(self):
        """
        :return: A string representation of the object
        """
        return "({idc}, {i}, {zi}, {ci}, {st})".format(idc=str(self.ID_C), i=str(self.i), zi=str(self.z_i.hex()),
                                                       ci=str(self.c_i), st=str(self.S_t))
