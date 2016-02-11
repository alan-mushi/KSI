import logging
import requests
from datetime import datetime, timedelta
from time import sleep
from copy import copy

from ksi.certificate import Certificate
from ksi.keys import Keys
from ksi.identifier import Identifier
from ksi.hash import hash_factory
from ksi.merkle_tree import Node
from ksi.ksi_server import KSIServer
from ksi.ksi_messages import TimestampRequest, TimestampResponse, KSIErrorCodes
from ksi.signverify import Signature
from ksi.dao import DAOClient
from ksi import API_ROUTE_BASE, API_HOST_PORT


class KSIClient:
    """
    Class acting as the client.

    The special case mentioned here happen when z_i is at a pair offset.
    The problem is exposed in "Efficient Quantum-Immune Keyless Signatures with Identity" page 9, section 3.1, Fig 4.
    Because we are hashing one additional step every i pair the algorithms need to "go" one step further.
    To address this special case we detect it as soon as possible (i.e. in __compute_hash_chain__) and mask the special
    node (z_i) to the recursive algorithm (because it is harder to patch).
    Masking is done by running __compute_hash_chain_step__ on z_i.parent.parent instead of z_i.parent, then we add the
    masked node manually (along with the special node coloring for graphviz).
    Pair offset z_i are always on the right child of their parent, see ksi.Keys for the implementation.

    Notation:
        x = hash(message || z_i)
    """

    def __init__(self, server: KSIServer, dao: DAOClient, certificate: Certificate=None, keys: Keys=None,
                 ID_C_str: str="client", api_user: str="", api_password: str="", api_ID_S: str=""):
        """
        Create a new client with the provided parameters.
        This constructor support 2 "modes": local and API. API uses the REST API (requires a server). The local variant
        is the "legacy" version, although it is great for testing purposes (i.e. with travis or unit-testing).
        To use the local version you must set the server argument and leave api_* arguments. To use the API you do the
        opposite, that is set server to None and fill api_*.
        :param server: The server to ask for timestamps
        :type server: KSIServer
        :param certificate: The client's certificate. It can be None in which case it is filled with self.keys.
        :type certificate: Certificate
        :param keys: The client's keys. It can be None in which case it is generated with the default values.
        :type keys: Keys
        :param ID_C_str: The client's identifier string
        :type ID_C_str: str
        :param api_user: The client's username for the API HTTP Basic Auth
        :type api_user: str
        :param api_password: The client's password for the API HTTP Basic Auth
        :type api_password: str
        :param api_ID_S: The ID_S for the server if you are using the API (i.e. server must be None)
        :type api_ID_S: str
        """
        assert isinstance(dao, DAOClient)
        assert isinstance(api_user, str) and isinstance(api_password, str) and isinstance(api_ID_S, str)
        self.server = server

        if self.server:
            assert isinstance(server, KSIServer) and api_ID_S == "" and api_user == "" and api_password == ""
            self.server_id = server.ID_S
        else:
            assert api_ID_S != "" and api_user != "" and api_password != ""
            self.server_id = Identifier(api_ID_S)

        self.dao = dao
        self.keys = keys
        self.api_user = api_user
        self.api_password = api_password

        # Generate keys with default values
        if not self.keys:
            self.keys = Keys()

        self.certificate = certificate

        # Configure the user's certificate from self.keys, t_0 is the current UTC time
        if not self.certificate:
            assert isinstance(self.keys, Keys)

            z_0 = self.keys.keys[0].hash
            r = self.keys.hash_tree_root.hash
            t_0 = datetime.utcnow()
            self.certificate = Certificate(Identifier(ID_C_str), z_0, r, t_0, self.server_id, self.keys.l)

        dao.publish_certificate(self.certificate)

        # Dictionary of requests made (indexed by x)
        self.requests = {}
        self.logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def sign(self, message: bytes, use_rest_api=False):
        """
        Ask the server to sign the message.
        At the end of this function self.requests will contain an entry at x for self.sign_callback().
        :param message: The message to sign
        :type message: bytes
        :param use_rest_api: Set to True if you want to use the remote REST API, False otherwise (e.g. travis)
        :type use_rest_api: bool
        """
        assert isinstance(message, bytes) and isinstance(use_rest_api, bool)

        current_time = datetime.utcnow()
        self.logger.debug("Sign request at %s for message: %s", current_time.isoformat(), message)

        # Assert we have a z_i to sign this message
        if not (current_time < self.certificate.t_0 + timedelta(seconds=self.keys.l)):
            self.logger.error("Attempt to sign with an outdated certificate!")
            raise ValueError

        # Compute the time difference between now and t_0 of the certificate
        time_delta = current_time - self.certificate.t_0  # type: timedelta
        # time_delta + 1 is meant to correct the index (in case we sign using the first z_i we want to use z_1 and
        # not z_0)
        time_delta_offset = int(time_delta.total_seconds()) + 1

        if time_delta_offset < 0:
            self.logger.error("Attempt to sign with a certificate beginning in the future!")
            raise ValueError

        # Take the appropriate z_i from the list (exclude the first item being z_0)
        z_i = self.keys.keys[time_delta_offset]  # type: Node
        self.logger.debug("\tz_i used to sign: %s", z_i.hash.hex())

        # x = hash(message || z_i)
        x = hash_factory(data=bytes(message) + z_i.hash)
        self.logger.debug("\tx computed: %s", x.hexdigest())
        # Insert x in self.requests
        self.requests[x.hexdigest()] = (z_i, time_delta_offset, x)
        request = TimestampRequest(x.digest(), self.certificate.id_client)

        # Create the request and send it to the server to get S_t
        if use_rest_api:
            assert self.api_user != "" and self.api_password != ""
            r = requests.post(API_HOST_PORT + API_ROUTE_BASE + 'sign', data=request.to_json(),
                              auth=(self.api_user, self.api_password),
                              headers={'Content-Type': 'application/json'})
            response = TimestampResponse.from_json_dict(r.json())
            self.sign_callback(response)

        else:
            self.server.send_request(request, lambda _response: self.sign_callback(_response))

    def sign_callback(self, response: TimestampResponse):
        """
        Called when the server did the timestamp on our timestamp request.
        The signature is added only if: response.status_code == KSIErrorCodes.NO_ERROR
        :param response: The timestamp response for a request
        :type response: TimestampResponse
        """
        assert isinstance(response, TimestampResponse)
        self.logger.debug("Got a response for the timestamp request %s: %s", response.x.hex(), response)

        if response.status_code != KSIErrorCodes.NO_ERROR:
            self.logger.info("Got a response with an error status code (%s): %s", str(response.status_code), str(response))
            return

        z_i, i, x = self.requests[response.x.hex()]
        hash_chain = self.__compute_hash_chain__(z_i, i % 2 == 0)  # type: Node

        # Mandatory, sleep one second before releasing the key otherwise forgery is possible
        sleep(1)

        # Add the finalized signature to self.signatures for publication
        sig = Signature(self.certificate.id_client, i, z_i.hash, hash_chain, response)
        self.dao.publish_signature(x, sig)

    def __compute_hash_chain__(self, z_i: Node, pair_i: bool) -> Node:
        """
        Clone the nodes used in the hash chain (z_i to root of the Merkle tree).
        :param z_i: The node at which to start the hash chain (bottom to top)
        :type z_i: Node
        :param pair_i: True if the index of z_i is pair (i.e. this is a special case, see the class documentation)
        :type pair_i: bool
        :return: The root of the hash chain
        :rtype: Node
        """
        assert isinstance(z_i, Node)
        assert isinstance(z_i.parent, Node)

        # i is pair so z_i is a special case
        if pair_i:
            z_i.set_mark_z_i()
            # Go up one level
            z_i = z_i.parent
            assert isinstance(z_i.parent, Node)

        # Call the recursive function to clone nodes on the hash chain
        hash_chain_node = self.__compute_hash_chain_step__(z_i.parent, z_i)
        z_i.set_mark_z_i()

        # Set the z_i mark on the hash chain (left child)
        if hash_chain_node.left_child and hash_chain_node.left_child.uuid == z_i.uuid:
            if not pair_i:
                hash_chain_node.left_child.set_mark_z_i()

            # Set the exception mark
            if hash_chain_node.right_child:
                hash_chain_node.right_child.set_mark_exception()
                z_i.parent.right_child.set_mark_exception()

        if pair_i:
            z_i.set_mark_exception()
            # Go down one level
            z_i = z_i.right_child
            # This node was left-out with the call to __compute_hash_chain_step__() so we need to add it ourselves
            tmp = copy(z_i)
            # Link tmp to its parent
            tmp.parent = hash_chain_node.right_child
            # Link the parent to tmp
            hash_chain_node.right_child.right_child = tmp
            hash_chain_node.right_child.set_mark_exception()

        # Set the z_i mark on the hash chain (right child)
        if hash_chain_node.right_child and hash_chain_node.right_child.uuid == z_i.uuid:
            hash_chain_node.right_child.set_mark_z_i()

        # We want the whole tree so we need to get to the root of it
        while hash_chain_node.parent:
            hash_chain_node = hash_chain_node.parent

        return hash_chain_node

    def __compute_hash_chain_step__(self, node: Node, origin_node: Node) -> Node:
        """
        Recursive function called to compute the hash chain.
        The hash chain is computed bottom (z_i) to top (root).
        This function only compute a "step" or level in the hash chain.
        As implemented the Node class _need_ a hash value so the clone node have the same value as the "reference" node.
        :param node: The node at the level we are at (must have origin_node as left or right child node)
        :type node: Node
        :param origin_node: The node from which this function call originated (must have node for parent)
        :type origin_node: Node
        :return: None if called at root level or a clone of the node we started at
        """
        # Current cloned node (the level we are at)
        current_node = None

        # This algorithm shall end when trying to be above the root
        if not node:
            return current_node

        node.set_mark_compute()
        # Apply the same algorithm for our parent
        parent_node = self.__compute_hash_chain_step__(node.parent, node)

        # If the call originate from the left child
        if node.left_child is origin_node:
            node.right_child.set_mark()
        else:
            node.left_child.set_mark()

        right_node = copy(node.right_child)  # type: Node
        left_node = copy(node.left_child)  # type: Node

        current_node = copy(node)  # type: Node
        current_node.left_child = left_node
        current_node.right_child = right_node
        current_node.set_mark_compute()

        if parent_node:
            # Link the parent's left child node to the current node
            if parent_node.left_child.hash == current_node.hash:
                parent_node.left_child = current_node

            # Link the parent's right child node to the current node
            elif parent_node.right_child.hash == current_node.hash:
                parent_node.right_child = current_node

        # Link current node to it's parent
        current_node.parent = parent_node

        return current_node

    def verify(self):
        # TODO
        pass
