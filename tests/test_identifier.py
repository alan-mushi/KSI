from unittest import TestCase
from ksi import IDENTIFIER_SEPARATOR, IDENTIFIER_BASE_NAME
from ksi.identifier import Identifier


class TestIdentifier(TestCase):
    def test_default(self):
        # Nothing special, just ensuring complete code coverage

        normal_ident_str = "herculepoirot"
        normal_ident = Identifier(normal_ident_str)
        print("id for \"" + normal_ident_str + "\": \"" + str(normal_ident) + "\"")
        assert str(normal_ident) == IDENTIFIER_BASE_NAME + normal_ident_str
