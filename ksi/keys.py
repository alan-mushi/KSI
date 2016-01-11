from os import urandom
from math import log2
from ksi.hash import *
from ksi.merkle_tree import *


class Keys:
    """
    Keys are the equivalent of z_i in KSI
    """

    def __init__(self, l=2 ** 16, seed=b'', seed_size=130):
        # TODO handle the rest of public/private key components
        """
        Constructor for keys
        :param l: The number of keys to generate for the Merkle tree (e.g. [z_1...z_l]), must be a power of two
        :param seed: The seed, mainly for testing purposes, s_l = hash(seed)
        :param seed_size: The size of the seed to generate (if seed is not supplied)
        """
        assert isinstance(l, int) and self.__is_power_of_2__(l)
        assert isinstance(seed, bytes)
        assert isinstance(seed_size, int)
        self.l = l
        self.seed = seed
        self.seed_size = seed_size
        self.keys = []
        self.__gen_keys__()
        self.__gen_merkle_tree__()

    @staticmethod
    def __is_power_of_2__(num):
        return ((num & (num - 1)) == 0) and num > 0

    def __gen_keys__(self):
        """
        Generate the z_i hash values
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

    def __gen_merkle_tree__(self):
        """
        Generate the Merkle hash tree
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
    def __gen_parent_level_tree__(tree_stage_child):
        """
        Generate one parent stage of a Merkle tree given the child stage.
        Here stage refers to "layers" or "lines" in a classic Merkle tree representation.
        :param: tree_stage_child A list of child nodes
        :return: A list of parent nodes
        """
        tree_stage = []
        i = 0

        for left_node, right_node in zip(tree_stage_child[0::2], tree_stage_child[1::2]):
            tree_stage.insert(i, Node(left_node, right_node))
            i += 1

        return tree_stage
