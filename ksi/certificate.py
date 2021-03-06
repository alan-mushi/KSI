from datetime import datetime

from ksi.identifier import Identifier
from ksi.keys import is_power_of_2


class Certificate:
    """
    KSI clients's certificates.
    This class is an empty shell as it is only used for presentation of the underlying data.
    """

    def __init__(self, id_client: Identifier, z_0: bytes, r: bytes, t_0: datetime, id_server: Identifier,
                 l: int=2 ** 16):
        """
        Create a ksi client's certificate.
        :param id_client: The Identifier of the client
        :type id_client: Identifier
        :param z_0: The last computed hash, it is _not_ part of the hash tree taken from ksi.Keys.keys[0].hash
        :type z_0: bytes
        :param r: The root of the hash tree taken from ksi.Keys.hash_tree_root.hash
        :type r: bytes
        :param t_0: The time at which the certificate becomes valid
        :type t_0: datetime
        :param id_server: The Identifier of the server
        :type id_server: Identifier
        :return:
        """
        assert isinstance(id_client, Identifier) and isinstance(id_server, Identifier)
        assert isinstance(z_0, bytes) and isinstance(r, bytes)
        assert isinstance(t_0, datetime)
        assert isinstance(l, int) and is_power_of_2(l)

        self.id_client = id_client
        self.z_0 = z_0
        self.r = r
        self.t_0 = t_0.replace(microsecond=0)
        self.id_server = id_server
        self.l = l

    def __str__(self):
        """
        :return: The friendly string representation.
        """
        return "({idc}, {z0}, {r}, {t0}, {ids})".format(idc=str(self.id_client),
                                                        z0=str(self.z_0.hex()),
                                                        r=str(self.r.hex()),
                                                        t0=str(self.t_0.isoformat()),
                                                        ids=str(self.id_server))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        identities_match = self.id_client == other.id_client and self.id_server == other.id_server
        bytes_match = self.z_0 == other.z_0 and self.r == other.r

        return identities_match and bytes_match and self.l == other.l and self.t_0 == other.t_0
