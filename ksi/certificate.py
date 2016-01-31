from datetime import datetime

from ksi.identifier import Identifier


class Certificate:
    """
    KSI clients's certificates.
    This class is an empty shell as it is only used for presentation of the underlying data.
    """

    def __init__(self, id_client, z0, r, t0, id_server):
        """
        Create a ksi client's certificate.
        :param id_client: The Identifier of the client (in ksi.Identifier)
        :param z0: The last computed hash, it is _not_ part of the hash tree (in bytes) taken from ksi.Keys.keys[0].hash
        :param r: The root of the hash tree (in bytes) taken from ksi.Keys.hash_tree_root.hash
        :param t0: The time at which the certificate becomes valid (in datetime.datetime)
        :param id_server: The Identifier of the server (in ksi.Identifier)
        :return:
        """
        assert isinstance(id_client, Identifier) and isinstance(id_server, Identifier)
        assert isinstance(z0, bytes) and isinstance(r, bytes)
        assert isinstance(t0, datetime)

        self.id_client = id_client
        self.z0 = z0
        self.r = r
        self.t0 = t0
        self.id_server = id_server

    def __str__(self):
        """
        :return: The friendly string representation.
        """
        ret = "( "
        ret += str(self.id_client) + ", "
        ret += str(self.z0.hex()) + ", "
        ret += str(self.r.hex()) + ", "
        ret += str(self.t0.isoformat()) + ", "
        ret += str(self.id_server) + " )"
        return ret
