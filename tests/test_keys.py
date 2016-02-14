from unittest import TestCase
from ksi.hash import *
from ksi.keys import Keys
from ksi.merkle_tree import Node
import graphviz


class TestKeys(TestCase):
    """
    Test for Merkle Tree / key generation.
    """
    def test_genKeys(self):
        assert HASH_ALGO == 'sha3_256'
        seed = b'ABCD'  # Do _not_ change the seed value or the following asserts will fail!

        keys = Keys(4, seed)

        # All nodes in the hash tree are checked
        # z_0
        assert str(keys.keys[0]) == '86fcf391e5741c8c72bf67c99d50d0157fb9b02db4e3e12ff9e87cbaebf7aa3e'
        # z_1_2 = h(z_1 || z_2)
        assert str(keys.hash_tree_root.left_child) == '387fec1a51aa8e02509065abf2903fdca4d72c59ce6a06b9c626b5b82d93b8d0'
        # z_3_4 = h(z_3 || z_4)
        assert str(keys.hash_tree_root.right_child) == '11553e32125fb3743c7f541e9b9dc7d088436f6cf1bfcd2e158e470df16138d5'
        # z_1_2_3_4 = h(z_1_2 || z_3_4)
        assert str(keys.hash_tree_root) == '79151d0a354254f666c9652003ec58a667cec715bab1f09fb5080ab5c31d9673'

        assert keys.hash_tree_root.right_child.left_child.is_leaf() is True

        # Merkle tree diagram
        keys.hash_tree_root.clear_mark()  # This is for code coverage
        g = graphviz.Digraph(name="merkle tree", directory="./output", format="dot", node_attr={"shape": "box"})
        g = keys.hash_tree_root.to_graphviz(g)
        g.render()

        # z_i diagram
        g_z = graphviz.Digraph(name="z_i", directory="./output", format="dot", node_attr={"shape": "box"},
                               edge_attr={"color": "red"})
        last_idx = len(keys.keys) - 1
        g_z.node(str(keys.keys[last_idx].uuid), label="z_" + str(last_idx) + " : " + keys.keys[last_idx].short_hex())

        for i in range(last_idx, 0, -1):
            g_z.node(str(keys.keys[i - 1].uuid), label="z_" + str(i - 1) + " : " + keys.keys[i - 1].short_hex())
            g_z.edge(str(keys.keys[i].uuid), str(keys.keys[i - 1].uuid))

        g_z.node(seed.hex(), label="seed : " + str(seed))
        g_z.edge(seed.hex(), str(keys.keys[last_idx].uuid))
        g_z.render()

    def test_genKeysRandom(self):
        # Test with random seed
        random_keys = Keys(2**4)

    def test_coverage(self):
        # For total coverage
        with self.assertRaises(AttributeError):
            Node()
