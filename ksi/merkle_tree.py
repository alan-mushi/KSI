from ksi.hash import *
import graphviz


class Node:
    def __init__(self, left_child=None, right_child=None, hash: bytes=bytes()):
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
        The name of the node is its string representation but its label is only the first 16 chars of this
        representation for convenience.
        All nodes with mark_for_graphviz will be printed with the desired color, once added to the graph the
        mark_for_graphviz attribute is removed.
        :param graph: The graph object to update
        :return: The updated graph object
        """
        assert isinstance(graph, graphviz.Digraph) or isinstance(graph, graphviz.Graph)

        if self.mark_for_graphviz:
            graph.node(str(self), label=str(self)[0:16]+"...",
                       _attributes={"style": "filled", "fillcolor": self.mark_for_graphviz})
        else:
            graph.node(str(self), label=str(self)[0:16]+"...")

        # Reset the mark
        self.mark_for_graphviz = None

        if self.left_child:
            self.left_child.to_graphviz(graph)
            graph.edge(str(self), str(self.left_child))

        if self.right_child:
            self.right_child.to_graphviz(graph)
            graph.edge(str(self), str(self.right_child))

        return graph

    def set_mark_z_i(self):
        """
        Color the node in cyan for the next call to to_graphviz().
        This color corresponds to the z_i at the base of the hash chain.
        """
        self.mark_for_graphviz = "cyan"

    def set_mark(self):
        """
        Color the node in green for the next call to to_graphviz().
        This color corresponds to a node whose value is saved in the hash chain.
        """
        self.mark_for_graphviz = "green"

    def set_mark_compute(self):
        """
        Color the node in yellow for the next call to to_graphviz().
        This color correspond to a node of the hash chain we need to compute.
        """
        self.mark_for_graphviz = "yellow"

    def set_mark_exception(self):
        """
        Color the node in blue for the next call to to_graphviz().
        This color correspond to a special case when z_i is pair, z_i+1 is thus impair but we cannot include z_i+1 in
        the hash chain for obvious forgery reasons.
        """
        self.mark_for_graphviz = "blue"

    def clear_mark(self):
        """
        Removes mark_for_graphviz for the whole sub-tree
        """
        self.mark_for_graphviz = None

        if self.left_child:
            self.left_child.clear_mark()

        if self.right_child:
            self.right_child.clear_mark()
