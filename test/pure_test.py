# -*- coding: utf-8 -*-
# Copyright (C) 2015 Björn Edström <be@bjrn.se>

import signify.pure as signify
import unittest


class SignifyTest(unittest.TestCase):

    KAT = [
        {
            'pub': b"""untrusted comment: bjorntest public key
RWQ100QRGZoxU+Oy1g7Ko+8LjK1AQLIEavp/NuL54An1DC0U2cfCLKEl
""",
            'priv': b"""untrusted comment: bjorntest secret key
RWRCSwAAACqHVbmAUokJcTpgKhRbw+/W+Q7nrVPi3eU100QRGZoxU86ZWb3NjEp9ScrFddFy0o2D1KtZ0440imfaWmUebGfs0Hm+Fm9SCtaJgtjFtrUlPlmnjksY8zdcXr2NvjLsr0A=
""",
            'message': b"""my message
""",
            'sig': b"""untrusted comment: signature from bjorntest secret key
RWQ100QRGZoxU/gjzE8m6GYtfICqE0Ap8SdXRSHrpjnSBKMc2RMalgi5RKrEHmKfTmcsuB9ZzDCo6K6sYEqaEcEnnAFa0zCewAg=
""",
            'brokensig': b"""untrusted comment: signature from bjorntest secret key
RWQ100QRGZoxU/gjzE8m6GYtfICqE0Ap8SdXRSHrpjnSBKMc2RMXlgi5RKrEHmKfTmcsuB9ZzDCo6K6sYEqaEcEnnAFa0zCewAg=
""",
            'embedded': b"""untrusted comment: signature from bjorntest secret key
RWQ100QRGZoxU/gjzE8m6GYtfICqE0Ap8SdXRSHrpjnSBKMc2RMalgi5RKrEHmKfTmcsuB9ZzDCo6K6sYEqaEcEnnAFa0zCewAg=
my message
"""
            }
        ]

    def test_extraction(self):
        self.assertEquals(
            b'\xe3\xb2\xd6\x0e\xca\xa3\xef\x0b\x8c\xad@@\xb2\x04j\xfa\x7f6\xe2\xf9\xe0\t\xf5\x0c-\x14\xd9\xc7\xc2,\xa1%',
            signify.PublicKey.from_bytes(self.KAT[0]['pub']).raw())

        sk = signify.SecretKey.from_bytes(self.KAT[0]['priv'])
        sku = sk.unprotect('test')
        self.assertEquals(
            b'D@\xd9\xca\xb2\x96;\xa0^\xbb\x16\xc8\x0f\xf7Y=(hu\x85\xbd\xe4i\xf6\xcf\x0f\xfb#\xc1\xfa\xe0\xa1\xe3\xb2\xd6\x0e\xca\xa3\xef\x0b\x8c\xad@@\xb2\x04j\xfa\x7f6\xe2\xf9\xe0\t\xf5\x0c-\x14\xd9\xc7\xc2,\xa1%',
            sku.raw_secret_key())

    def test_verify_success(self):
        self.assertTrue(
            signify.verify(signify.PublicKey.from_bytes(self.KAT[0]['pub']),
                           signify.Signature.from_bytes(self.KAT[0]['sig']),
                           self.KAT[0]['message']))

    def test_sign(self):
        sk = signify.SecretKey.from_bytes(self.KAT[0]['priv'])
        sku = sk.unprotect('test')
        sig = signify.sign(sku,
                           self.KAT[0]['message'])

        self.assertEquals(self.KAT[0]['sig'], sig.to_bytes())

    def test_sign_embedded(self):
        sk = signify.SecretKey.from_bytes(self.KAT[0]['priv'])
        sku = sk.unprotect('test')
        sig = signify.sign(sku,
                           self.KAT[0]['message'],
                           True)

        self.assertEquals(self.KAT[0]['embedded'], sig.to_bytes())

    def test_verify_embedded(self):
        self.assertTrue(
            signify.verify_embedded(signify.PublicKey.from_bytes(self.KAT[0]['pub']),
                                    self.KAT[0]['embedded']))

    def test_decrypt_secret_wrong_password(self):
        self.assertRaises(KeyError,
                          signify.SecretKey.from_bytes(self.KAT[0]['priv']).unprotect,
                          'wrongpassword')

    def test_verify_failure(self):
        self.assertRaises(
            signify.InvalidSignature,
            signify.verify, signify.PublicKey.from_bytes(self.KAT[0]['pub']),
                            signify.Signature.from_bytes(self.KAT[0]['brokensig']),
                            self.KAT[0]['message'])

    def test_generate_sign_no_password(self):
        pub, priv = signify.generate('test', None)

        self.assertTrue(pub.to_bytes().startswith(b'untrusted comment: test public key'))
        self.assertTrue(priv.to_bytes().startswith(b'untrusted comment: test secret key'))

        sku = priv.unprotect(None)
        sig = signify.sign(sku,
                           b'My Message')

        self.assertTrue(
            signify.verify(pub,
                           sig,
                           b'My Message'))

    def test_generate_no_comment(self):
        pub, priv = signify.generate(None, None)

        self.assertTrue(pub.to_bytes().startswith(b'untrusted comment: signify public key'))
        self.assertTrue(priv.to_bytes().startswith(b'untrusted comment: signify secret key'))

    def test_generate_sign_with_password(self):
        pub, priv = signify.generate(None, 'testpassword')

        self.assertTrue(pub.to_bytes().startswith(b'untrusted comment: signify public key'))
        self.assertTrue(priv.to_bytes().startswith(b'untrusted comment: signify secret key'))

        sku = priv.unprotect('testpassword')
        sig = signify.sign(sku,
                           b'My Message')

        self.assertTrue(
            signify.verify(pub,
                           sig,
                           b'My Message'))


if __name__ == '__main__':
    unittest.main()
