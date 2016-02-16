from datetime import datetime
from unittest import TestCase
from Crypto.Signature.PKCS1_v1_5 import PKCS115_SigScheme
from os import path

from ksi.identifier import Identifier
from ksi.ksi_messages import KSIErrorCodes
from ksi.signverify import SignVerify, TimestampResponse
from ksi.hash import hash_factory


filename_public_key = "output/public.pem"
filename_private_key = "output/private.pem"
signed_resp = None
signed_msg = None


class TestSignVerify(TestCase):
    signverify = SignVerify()

    def test_0_generate_keys(self):

        TestSignVerify.signverify.generate_keys()  # type: SignVerify

        self.assertIsNotNone(TestSignVerify.signverify.key)
        self.assertIsNotNone(TestSignVerify.signverify.signer_verifier)

    def test_1_export_keys(self):
        TestSignVerify.signverify.export_keys(filename_public_key, filename_private_key)

        self.assertTrue(path.isfile(filename_private_key))
        self.assertTrue(path.isfile(filename_public_key))

    def test_3_import_private_keys(self):
        TestSignVerify.signverify.import_private_keys(filename_private_key)

        self.assertIsInstance(TestSignVerify.signverify.signer_verifier, PKCS115_SigScheme)
        self.assertTrue(TestSignVerify.signverify.signer_verifier.can_sign())

    def test_4_import_public_keys(self):
        TestSignVerify.signverify.import_public_keys(filename_public_key)

        self.assertIsInstance(TestSignVerify.signverify.signer_verifier, PKCS115_SigScheme)
        self.assertFalse(TestSignVerify.signverify.signer_verifier.can_sign())

    def test_5_sign(self):
        global signed_resp, signed_msg
        TestSignVerify.signverify.import_private_keys(filename_private_key)

        x = hash_factory(data=b'ABCD')
        t_resp = TimestampResponse(x, Identifier("server"), Identifier("client"), datetime.utcnow(),
                                   KSIErrorCodes.NO_ERROR)

        signed_msg, signed_resp = TestSignVerify.signverify.sign(t_resp)

    def test_6_verify(self):
        global signed_resp, signed_msg
        TestSignVerify.signverify.import_public_keys(filename_public_key)

        self.assertTrue(TestSignVerify.signverify.verify(signed_msg, signed_resp))
        self.assertFalse(TestSignVerify.signverify.verify(b'1234', signed_resp))
