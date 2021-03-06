from ksi import IDENTIFIER_BASE_NAME, IDENTIFIER_SEPARATOR


class Identifier:
    """
    Identifier for KSI. Used for the signature, certificate and verification steps.
    The notation used is reverse DNS (e.g. "org.ksi.herculepoirot" for the user "herculepoirot")
    """

    def __init__(self, id: str):
        """
        Create a new identifier with a given basename and id.
        The parameter _need_ to be a printable string (lowercase alphanumeric and ascii encoded).
        :param id: The id (rightmost field in reverse DNS notation)
        """
        assert isinstance(id, str) and id.isprintable()
        assert id.islower() and id.isalnum() and id.find(IDENTIFIER_SEPARATOR) == -1

        self.id = IDENTIFIER_BASE_NAME + str(id.encode(encoding='ascii').lower(), encoding='ascii')

    def __str__(self):
        return self.id

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.id == other.id
