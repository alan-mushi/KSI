import json
import pickle
from Crypto.PublicKey import RSA  # ElGamal and DSA are also available
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from base64 import standard_b64encode, standard_b64decode

from ksi import SIGN_KEY_LEN, SIGN_KEY_FORMAT, IDENTIFIER_BASE_NAME
from ksi.ksi_messages import TimestampResponse, bytes_to_base64_str
from ksi.merkle_tree import Node
from ksi.identifier import Identifier
from ksi.bench_decorator import benchmark_decorator


class Signature:
    """
    Convenience class to hold a signature.
    """

    def __init__(self, ID_C: Identifier, i: int, z_i: bytes, c_i: Node, S_t: TimestampResponse, message: bytes):
        """
        Create a signature object with the provided arguments.
        :param ID_C: The client's identifier
        :type ID_C: Identifier
        :param i: the time offset in the list of z_i
        :type i: int
        :param z_i: The z_i used to compute the hash chain
        :type z_i: bytes
        :param c_i: The hash chain
        :type c_i: Node
        :param S_t: S_t (aka the TimestampResponse object delivered by the server)
        :type S_t: TimestampResponse
        :param message: The message signed
        :type message: bytes
        """
        assert isinstance(ID_C, Identifier)
        assert isinstance(i, int)
        assert isinstance(z_i, bytes) and isinstance(message, bytes)
        assert isinstance(c_i, Node)
        assert isinstance(S_t, TimestampResponse)

        self.ID_C = ID_C
        self.i = i
        self.z_i = z_i
        self.c_i = c_i
        self.S_t = S_t
        self.message = message

    def __str__(self):
        """
        :return: A string representation of the object
        """
        return "({idc}, {i}, {zi}, {ci}, {msg}, {st})".format(idc=str(self.ID_C), i=str(self.i), zi=str(self.z_i.hex()),
                                                              ci=str(self.c_i), msg=self.message.hex(),
                                                              st=str(self.S_t))

    def to_json(self) -> str:
        """
        :return: Return the JSON string representation of the Signature object.
        :rtype: str
        """
        return json.dumps({'ID_C': str(self.ID_C),
                           'i': self.i,
                           'z_i': bytes_to_base64_str(self.z_i),
                           'c_i': bytes_to_base64_str(pickle.dumps(self.c_i)),
                           'msg': bytes_to_base64_str(self.message),
                           'S_t': self.S_t.to_json()})

    @staticmethod
    def from_json(json_obj: dict):
        """
        :param json_obj: A JSON representation of the Signature object
        :type json_obj: dict
        :return: A new Signature built from the json_obj parameter
        :rtype: Signature
        """
        assert 'ID_C' in json_obj
        assert 'i' in json_obj
        assert 'z_i' in json_obj
        assert 'c_i' in json_obj
        assert 'msg' in json_obj
        assert 'S_t' in json_obj

        ID_C = Identifier(json_obj['ID_C'][len(IDENTIFIER_BASE_NAME):])
        i = json_obj['i']
        z_i = standard_b64decode(json_obj['z_i'])
        c_i = pickle.loads(standard_b64decode(json_obj['c_i']))
        msg = standard_b64decode(json_obj['msg'])
        S_t = TimestampResponse.from_json_dict(json_obj['S_t'])

        return Signature(ID_C, i, z_i, c_i, S_t, msg)


class SignVerify:
    """
    Sign and Verify cryptographic signatures.
    The signature use RSA with PKCS1 v1.5
    The 'message' refer to : x || '|' || t.isoformat() || '|' || ID_C.
    What is signed is actually: Crypto.SHA.new(message)
    By default the signatures are base64 encoded.

    This class use global configuration variables (see __init__.py):
    - SIGN_KEY_FORMAT
    - SIGN_KEY_LEN
    """

    def __init__(self):
        self.key = None
        self.signer_verifier = None

    def generate_keys(self, key_len: int=SIGN_KEY_LEN):
        """
        Generate a pair of Public/Secret RSA key of length key_len..
        :param key_len: The length of the key to generate
        :type key_len: int
        """
        assert isinstance(key_len, int)

        self.key = RSA.generate(key_len)
        self.signer_verifier = PKCS1_v1_5.new(self.key)

    def import_private_keys(self, filename: str):
        """
        Import the private key from the file named filename, used by the signer.
        :param filename: The file containing the private key
        :type filename: str
        """
        assert isinstance(filename, str) and len(filename) != 0

        with open(filename, 'rb') as file:
            self.key = RSA.importKey(file.read())

        if not self.key.has_private():
            self.key = None
            raise ValueError("No private key found in %s", filename)

        self.signer_verifier = PKCS1_v1_5.new(self.key)

    def import_public_keys(self, filename: str):
        """
        Import the public key from the file named filename, used by the verifier.
        :param filename: The file containing the public key
        :type filename: str
        """
        assert isinstance(filename, str) and len(filename) != 0

        with open(filename, 'rb') as file:
            self.key = RSA.importKey(file.read())

        if not self.key.publickey():
            self.key = None
            raise ValueError("No public key found in %s", filename)

        self.signer_verifier = PKCS1_v1_5.new(self.key)

    def export_keys(self, filename_public_key: str, filename_private_key: str):
        """
        Export both private an public keys to file.
        :param filename_public_key: The public key will be written to this filename.
        :type filename_public_key: str
        :param filename_private_key: The private key will be written to this filename.
        :type filename_private_key: str
        """
        assert self.key and self.key.has_private() and self.key.publickey() and self.key.can_sign()
        assert isinstance(filename_private_key, str) and len(filename_private_key) != 0
        assert isinstance(filename_public_key, str) and len(filename_public_key) != 0

        with open(filename_public_key, 'wb') as file:
            file.write(self.key.publickey().exportKey(SIGN_KEY_FORMAT))

        with open(filename_private_key, 'wb') as file:
            file.write(self.key.exportKey(SIGN_KEY_FORMAT))

    @benchmark_decorator
    def sign(self, sig: TimestampResponse, base64_encode: bool=True) -> (bytes, TimestampResponse):
        """
        Fill the field sig.signature by signing the message.
        This is a proxy method for self._sign().
        :param sig: The TimestampResponse object to fill
        :type sig: TimestampResponse
        :param base64_encode: True to encode the signature in base64 (standard)
        :type base64_encode: bool
        :return: (message, filled TimestampResponse)
        """
        assert isinstance(sig, TimestampResponse)

        msg = self.msg(sig)
        sig.signature = self._sign(msg, base64_encode)

        return msg, sig

    def _sign(self, message: bytes, base64_encode: bool=True) -> bytes:
        """
        Sign a message.
        :param message: The message to sign
        :type message: bytes
        :param base64_encode: True to encode the signature in base64 (standard)
        :type base64_encode: bool
        :return: The signature associated with the message in bytes
        """
        assert isinstance(message, bytes) and self.key and self.signer_verifier and self.signer_verifier.can_sign()

        # We can't sign "arbitrary bytes" and the hash must comply with the ones of the Crypto lib...
        res = self.signer_verifier.sign(SHA.new(message))

        if base64_encode:
            res = standard_b64encode(res)

        return res

    @staticmethod
    def msg(S_t: TimestampResponse) -> bytes:
        """
        Return the message to be signed as bytes: x || '|' || t.isoformat() || '|' || ID_C.
        '|' act as a separator.
        :param S_t: The timestamp response containing x and ID_C
        :type S_t: TimestampResponse
        :return: The concatenation of x, '|', t.isoformat(), '|' and ID_C as bytes
        """
        assert isinstance(S_t, TimestampResponse) and S_t.x and S_t.ID_C

        s_id_c = str(S_t.ID_C)
        S_t_x_bytes = S_t.x

        if not isinstance(S_t.x, bytes):
            S_t_x_bytes = S_t.x.digest()

        return S_t_x_bytes + b'|' + bytes(S_t.t.isoformat(), encoding='ascii') + b'|' + bytes(s_id_c, encoding="ascii")

    @benchmark_decorator
    def verify(self, msg: bytes, sig: TimestampResponse, base64_encoded: bool=True) -> bool:
        """
        Verify a Signature object, this is a proxy method for self._verify().
        :param msg: The signed message
        :type msg: bytes
        :param sig: The TimestampResponse object containing the signature
        :type sig: TimestampResponse
        :param base64_encoded: The signature is encoded in base64 (standard)
        :type base64_encoded: bool
        :return: True if the signature is correct for the message (see msg), False otherwise
        """
        assert isinstance(msg, bytes) and isinstance(sig, TimestampResponse) and self.key and self.key.publickey()

        return self._verify(msg, sig.signature, base64_encoded)

    def _verify(self, message: bytes, signature: bytes, base64_encoded: bool=True) -> bool:
        """
        Verify the signature on a message.
        :param message: The message associated with the signature
        :type message: bytes
        :param signature: The signature to verify
        :type signature: bytes
        :param base64_encoded: True if the signature is encoded in base64 (standard)
        :type base64_encoded: bool
        :return: True if the signature is correct for the message, False otherwise
        :rtype: bool
        """
        assert isinstance(message, bytes) and isinstance(signature, bytes) and self.key and self.key.publickey()

        _signature = signature

        if base64_encoded:
            _signature = standard_b64decode(_signature)

        return self.signer_verifier.verify(SHA.new(message), _signature)
