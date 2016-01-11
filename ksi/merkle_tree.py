from ksi.hash import *
import graphviz


class Node:
    def __init__(self, left_child=None, right_child=None, hash=bytes()):
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

        # In case we are dealing with a node (thus _not_ a leaf) we compute the hash value for it
        if self.hash == bytes():
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

    def is_leaf(self):
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
        :param graph: The graph object to update
        :return: The updated graph object
        """
        assert isinstance(graph, graphviz.Digraph) or isinstance(graph, graphviz.Graph)

        graph.node(str(self))

        if self.left_child:
            self.left_child.to_graphviz(graph)
            graph.edge(str(self), str(self.left_child))

        if self.right_child:
            self.right_child.to_graphviz(graph)
            graph.edge(str(self), str(self.right_child))

        return graph
