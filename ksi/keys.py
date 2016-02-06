from os import urandom
from math import log2
from ksi.hash import *
from ksi.merkle_tree import *


def is_power_of_2(num: int) -> bool:
    """
    Return true if num is a power of 2.
    :param num: The number to test
    :type num: int
    :return: True if num is a power of 2, False otherwise
    """
    return ((num & (num - 1)) == 0) and num > 0


class Keys:
    """
    Keys are the equivalent of z_i in KSI.

    "Special" nodes (i.e. z_i with a pair index) and their "decoy" nodes (i.e. the parents of z_i special nodes) are
    computed in __gen_keys__().
    """

    def __init__(self, l: int=2 ** 16, seed: bytes=b'', seed_size: int=130):
        """
        Constructor for keys
        :param l: The number of keys to generate for the Merkle tree (e.g. [z_1...z_l]), must be a power of two
        :type l: int
        :param seed: The seed, mainly for testing purposes, s_l = hash(seed)
        :type seed: bytes
        :param seed_size: The size of the seed to generate (if seed is not supplied)
        :type seed_size: int
        """
        assert isinstance(l, int) and is_power_of_2(l)
        assert isinstance(seed, bytes)
        assert isinstance(seed_size, int)

        self.l = l
        self.seed = seed
        self.seed_size = seed_size
        self.keys = []
        self.__gen_keys__()
        self.hash_tree_root = None
        self.__gen_merkle_tree__()

    def __gen_keys__(self):
        """
        Generate the z_i hash values.
        """
        if not self.seed:
            self.seed = urandom(int(self.seed_size))

        self.seed = bytes(self.seed)
        n_prev = Node(hash=hash_factory(data=self.seed).digest())
        self.keys.insert(0, n_prev)

        for i in range(1, self.l + 1):
            n = Node(hash=hash_factory(data=n_prev.hash).digest())
            self.keys.insert(0, n)
            n_prev = n

        # Add the decoy nodes as parents of pair nodes.
        # The pair nodes will _always_ be the right child of the decoy nodes.
        for i in range(2, self.l + 1, 2):
            n_pair = self.keys[i]  # type: Node
            n_impair_prev = self.keys[i-1]  # type: Node
            n_pair.parent = Node(hash=bytes(n_impair_prev.hash))
            n_pair.parent.right_child = n_pair

    def __gen_merkle_tree__(self):
        """
        Generate the Merkle hash tree.
        """
        tree_stage = []
        tree_stage_num = int(log2(self.l))
        current_tree_stage = self.keys[1:]

        for i in range(0, tree_stage_num):
            tree_stage.insert(i, self.__gen_parent_level_tree__(current_tree_stage))
            current_tree_stage = tree_stage[i]

        assert len(current_tree_stage) == 1

        self.hash_tree_root = current_tree_stage[0]

    @staticmethod
    def __gen_parent_level_tree__(tree_stage_child: list) -> list:
        """
        Generate one parent stage of a Merkle tree given the child stage.
        Here stage refers to "layers" or "lines" in a classic Merkle tree representation.
        :param: tree_stage_child A list of child nodes
        :return: A list of parent nodes
        """
        tree_stage = []
        i = 0

        for left_node, right_node in zip(tree_stage_child[0::2], tree_stage_child[1::2]):

            if right_node.parent:
                right_node = right_node.parent

            parent = Node(left_node, right_node)
            tree_stage.insert(i, parent)
            left_node.parent = parent
            right_node.parent = parent
            i += 1

        return tree_stage
