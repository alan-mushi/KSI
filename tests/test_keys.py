from unittest import TestCase
from ksi.hash import *
from ksi.keys import Keys
import graphviz


class TestKeys(TestCase):
    """
    Test for Merkle Tree / key generation.
    """
    def test_genKeys(self):
        seed = b'ABCD'  # Do _not_ change the seed value or the following asserts will fail!

        keys = Keys(4, seed)

        # All nodes in the hash tree are checked
        assert str(keys.keys[0]) == '86fcf391e5741c8c72bf67c99d50d0157fb9b02db4e3e12ff9e87cbaebf7aa3e'  # z_0
        assert str(
            keys.hash_tree_root.left_child) == '78374c3817ca88fa99707fb3ce4b6e30966116db2efc58781f22b8809c66fd63'  # z_1_2 = h(z_1 || z_2)
        assert str(
            keys.hash_tree_root.right_child) == '10169b69bffb4eb49bda7229aa97c4e3eae2b0c9560a8dafdb9130bab3e8de17'  # z_3_4 = h(z_3 || z_4)
        assert str(
            keys.hash_tree_root) == '297b51ad691fd3d8e17a253274581e2ea2c958c976bb2ad76bdce8b51c7937f4'  # z_1_2_3_4 = h(z_1_2 || z_3_4)

        # Merkle tree diagram
        g = graphviz.Digraph(name="merkle tree", directory="./output", format="dot", node_attr={"shape": "box"})
        g = keys.hash_tree_root.to_graphviz(g)
        g.render()

        # z_i diagram
        g_z = graphviz.Digraph(name="z_i", directory="./output", format="dot", node_attr={"shape": "box"},
                               edge_attr={"color": "red"})
        last_idx = len(keys.keys) - 1
        g_z.node(str(keys.keys[last_idx]), label="z_" + str(last_idx) + " : " + str(keys.keys[last_idx]))

        for i in range(last_idx, 0, -1):
            g_z.node(str(keys.keys[i - 1]), label="z_" + str(i - 1) + " : " + str(keys.keys[i - 1]))
            _label = "z_" + str(i) + " -> z_" + str(i - 1)
            g_z.edge(str(keys.keys[i]), str(keys.keys[i - 1]), label=_label)

        g_z.node(seed.hex(), label="seed : " + str(seed))
        g_z.edge(seed.hex(), str(keys.keys[last_idx]), label="seed -> z_4")
        g_z.render()
