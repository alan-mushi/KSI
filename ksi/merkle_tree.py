import graphviz
from enum import Enum, unique

from ksi.hash import *


@unique
class Mark(Enum):
    """
    Marks for graphviz
    """
    z_i = "cyan"
    regular = "green"
    exception = "blue"
    compute = "yellow"


class Node:
    # See comment on self.uuid
    ctr = 0

    def __init__(self, left_child=None, right_child=None, hash: bytes = b''):
        """
        Node constructor.
        If you want to create a leaf only set the hash.
        If you want to create a Merkle tree node only set left and right childs, the hash for the parent node will be
        computed automatically.
        :param left_child: (Optional) Construct the node with a left child node
        :param right_child: (Optional) Construct the node with a right child node
        :param hash: (Optional) Construct the node with a hash value (in bytes
        """
        assert isinstance(hash, bytes)

        self.parent = None
        self.left_child = left_child
        self.right_child = right_child
        self.hash = hash
        self.mark_for_graphviz = None

        # Universally Unique Identifier, used to identify a node
        self.uuid = Node.ctr
        Node.ctr += 1

        # In case we are dealing with a node (thus _not_ a leaf) we compute the hash value for it
        if self.hash == b'':
            self.__compute_hash__()

    def __compute_hash__(self):
        """
        Compute a hash value for self.hash = hash(left_child.hash || right_child.hash)
        """
        if self.left_child is None and self.right_child is None:
            raise AttributeError

        assert isinstance(self.left_child.hash, bytes)
        assert isinstance(self.right_child.hash, bytes)

        hash_concat = bytearray(self.left_child.hash) + bytearray(self.right_child.hash)
        self.hash = hash_factory(data=hash_concat).digest()

    def is_leaf(self) -> bool:
        """
        Return True if this node is a leaf.
        :return: Return True if this node is a leaf.
        """
        return self.left_child is None and self.right_child is None

    def __str__(self):
        """
        Used for pretty-printing the hex of self.hash
        :return: The hex string representation of self.hash
        """
        return self.hash.hex()

    def to_graphviz(self, graph):
        """
        Produces a standard tree print graph (left to right).
        To visualize install 'xdot' and 'graphviz' or change output format to 'png' or 'svg'.
        The name (in graphviz terminology) of the node is its uuid, its label is the first 16 chars of the node's hash
        in hexadecimal.
        All nodes with mark_for_graphviz will be printed with the desired color, once added to the graph
        mark_for_graphviz is set to None.
        :param graph: The graph object to update
        :return: The updated graph object
        """
        assert isinstance(graph, graphviz.Digraph) or isinstance(graph, graphviz.Graph)

        if self.mark_for_graphviz:
            graph.node(str(self.uuid), label=self.short_hex(),
                       _attributes={"style": "filled", "fillcolor": self.mark_for_graphviz.value})
        else:
            graph.node(str(self.uuid), label=self.short_hex())

        # Reset the mark
        self.mark_for_graphviz = None

        if self.left_child:
            self.left_child.to_graphviz(graph)
            graph.edge(str(self.uuid), str(self.left_child.uuid))

        if self.right_child:
            self.right_child.to_graphviz(graph)
            graph.edge(str(self.uuid), str(self.right_child.uuid))

        return graph

    def set_mark_z_i(self):
        """
        Color the node in cyan for the next call to to_graphviz().
        This color corresponds to the z_i at the base of the hash chain.
        """
        self.mark_for_graphviz = Mark.z_i

    def set_mark(self):
        """
        Color the node in green for the next call to to_graphviz().
        This color corresponds to a node whose value is saved in the hash chain.
        """
        self.mark_for_graphviz = Mark.regular

    def set_mark_compute(self):
        """
        Color the node in yellow for the next call to to_graphviz().
        This color correspond to a node of the hash chain we need to compute.
        """
        self.mark_for_graphviz = Mark.compute

    def set_mark_exception(self):
        """
        Color the node in blue for the next call to to_graphviz().
        This color correspond to a special case when z_i is pair, z_i+1 is thus impair but we cannot include z_i+1 in
        the hash chain for obvious forgery reasons.
        """
        self.mark_for_graphviz = Mark.exception

    def clear_mark(self):
        """
        Removes mark_for_graphviz for the whole sub-tree.
        """
        self.mark_for_graphviz = None

        if self.left_child:
            self.left_child.clear_mark()

        if self.right_child:
            self.right_child.clear_mark()

    def __copy__(self):
        """
        Copy constructor, only copy the hash, the uuid and the mark_for_graphviz (used by the hash chain algorithm).
        :return: A new object with copied hash, the same uuid and same mark_for_graphviz
        """
        new = Node(hash=bytes(self.hash))
        new.uuid = self.uuid
        new.mark_for_graphviz = None

        if self.mark_for_graphviz:
            new.mark_for_graphviz = self.mark_for_graphviz

        return new

    def short_hex(self) -> str:
        """
        Return the short hex name/notation of a node (used for labels in graphviz).
        :return: A string composed of the first 16 chars followed by "..."
        """
        return str(self)[:16] + "..."

    def hash_chain_compute_to_root(self) -> bytes:
        """
        Compute a hash chain bottom-to-top starting from the root.
        :return: The hash value for self
        :rtype: bytes
        """
        if self.mark_for_graphviz == Mark.compute:
            hash_concat = bytearray(self.left_child.hash_chain_compute_to_root()) + \
                          bytearray(self.right_child.hash_chain_compute_to_root())
            self.hash = hash_factory(data=hash_concat).digest()

        return self.hash
