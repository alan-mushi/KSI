import logging
from datetime import datetime, timedelta
from time import sleep

from ksi.certificate import Certificate
from ksi.keys import Keys
from ksi.identifier import Identifier
from ksi.hash import hash_factory
from ksi.merkle_tree import Node
from ksi.ksi_server import KSIServer
from ksi.ksi_messages import TimestampRequest, TimestampResponse
from ksi.signature import Signature


class KSIClient:
    """
    Class acting as the client.

    Notation:
        x = hash(message || z_i)
    """

    def __init__(self, server: KSIServer, certificate: Certificate=None, keys: Keys=None, ID_C_str: str="client"):
        """
        Create a new client with the provided parameters.
        :param server: The server to ask for timestamps
        :type server: KSIServer
        :param certificate: The client's certificate. It can be None in which case it is filled with self.keys.
        :type certificate: Certificate
        :param keys: The client's keys. It can be None in which case it is generated with the default values.
        :type keys: Keys
        :param ID_C_str: The client's identifier string
        :type ID_C_str: str
        """
        assert isinstance(server, KSIServer)

        self.server = server
        self.keys = keys

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
            self.certificate = Certificate(Identifier(ID_C_str), z_0, r, t_0, self.server.ID_S)

        # Dictionary of requests made (indexed by x)
        self.requests = {}
        # Dictionary of signatures (indexed by x)
        self.signatures = {}

    def sign(self, message: bytes):
        """
        Ask the server to sign the message.
        At the end of this function self.requests will contain an entry at x for self.sign_callback().
        :param message: The message to sign
        :type message: bytes
        """
        assert isinstance(message, bytes)

        current_time = datetime.utcnow()
        logging.debug("Sign request at %s for message: %s", current_time.isoformat(), message)

        # Assert we have a z_i to sign this message
        if not (current_time < self.certificate.t_0 + timedelta(seconds=self.keys.l)):
            logging.error("Attempt to sign with an outdated certificate!")
            raise ValueError

        # Compute the time difference between now and t_0 of the certificate
        time_delta = current_time - self.certificate.t_0  # type: timedelta
        # time_delta + 1 is meant to correct the index (in case we sign using the first z_i we want to use z_1 and
        # not z_0)
        time_delta_offset = int(time_delta.total_seconds()) + 1

        # Take the appropriate z_i from the list (exclude the first item being z_0)
        z_i = self.keys.keys[time_delta_offset]  # type: Node
        logging.debug("\tz_i used to sign: %s", z_i.hash.hex())

        if (time_delta_offset + 1) % 2 == 0:
            logging.critical("z_i+1 will leak in the hash chain (TODO is set)")

        # x = hash(message || z_i)
        x = hash_factory(data=bytes(message) + z_i.hash)
        logging.debug("\tx computed: %s", x.hexdigest())
        # Insert x in self.requests
        self.requests[x.hexdigest()] = (z_i, time_delta_offset, x)

        # Create the request and send it to the server to get S_t
        request = TimestampRequest(x, self.certificate.id_client)
        self.server.send_request(request, lambda response: self.sign_callback(response))

    def sign_callback(self, response: TimestampResponse):
        """
        Called when the server did the timestamp on our timestamp request.
        :param response: The timestamp response for a request
        :type response: TimestampResponse
        """
        assert isinstance(response, TimestampResponse)
        logging.debug("Got a response for the timestamp request %s: %s", response.x.hexdigest(), response)

        z_i, i, x = self.requests[response.x.hexdigest()]
        hash_chain = self.__compute_hash_chain__(z_i)  # type: Node

        sleep(1)  # Mandatory, sleep one second before releasing the key otherwise forgery is possible

        # Add the finalized signature to self.signatures for publication
        self.signatures[x] = Signature(self.certificate.id_client, i, z_i.hash, hash_chain, response)

    def __compute_hash_chain__(self, z_i: Node) -> Node:
        """
        Clone the nodes used in the hash chain (z_i to root of the Merkle tree).
        :param z_i: The node at which to start the hash chain (bottom to top)
        :type z_i: Node
        :return: The root of the hash chain
        """
        # TODO handle the impair node i
        assert isinstance(z_i, Node)

        # Call the recursive function to clone nodes on the hash chain
        hash_chain_node = self.__compute_hash_chain_step__(z_i.parent, z_i)
        z_i.set_mark_z_i()

        # Set the z_i mark on the hash chain (left child)
        if hash_chain_node.left_child and hash_chain_node.left_child.hash == z_i.hash:
            hash_chain_node.left_child.set_mark_z_i()

            # Set the exception mark (for _now_ z_i+1 *will* leak in the hash_chain)
            if hash_chain_node.right_child:
                hash_chain_node.right_child.set_mark_exception()
                z_i.parent.right_child.set_mark_exception()

        # Set the z_i mark on the hash chain (right child)
        if hash_chain_node.right_child and hash_chain_node.right_child.hash == z_i.hash:
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
        right_node = Node(hash=bytes(node.right_child.hash))
        left_node = Node(hash=bytes(node.left_child.hash))
        current_node = Node(left_child=left_node, right_child=right_node, hash=bytes(node.hash))

        # If the call originate from the left child
        if node.left_child is origin_node:
            node.right_child.set_mark()
            right_node.set_mark()

        else:
            node.left_child.set_mark()
            left_node.set_mark()

        if parent_node:
            # Link the parent's left child node to the current node
            if parent_node.left_child.hash == current_node.hash:
                parent_node.left_child = current_node

            # Link the parent's right child node to the current node
            elif parent_node.right_child.hash == current_node.hash:
                parent_node.right_child = current_node

        # Link current node to it's parent
        current_node.parent = parent_node
        current_node.set_mark_compute()

        return current_node

    def verify(self):
        # TODO
        pass
