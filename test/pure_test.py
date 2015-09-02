# -*- coding: utf-8 -*-
# Copyright (C) 2015 Björn Edström <be@bjrn.se>

import signify.pure as signify
import unittest


class SignifyTest(unittest.TestCase):

    KAT = [
        {
            'pub': """untrusted comment: bjorntest public key
RWQ100QRGZoxU+Oy1g7Ko+8LjK1AQLIEavp/NuL54An1DC0U2cfCLKEl
""",
            'priv': """untrusted comment: bjorntest secret key
RWRCSwAAACqHVbmAUokJcTpgKhRbw+/W+Q7nrVPi3eU100QRGZoxU86ZWb3NjEp9ScrFddFy0o2D1KtZ0440imfaWmUebGfs0Hm+Fm9SCtaJgtjFtrUlPlmnjksY8zdcXr2NvjLsr0A=
""",
            'message': """my message
""",
            'sig': """untrusted comment: signature from bjorntest secret key
RWQ100QRGZoxU/gjzE8m6GYtfICqE0Ap8SdXRSHrpjnSBKMc2RMalgi5RKrEHmKfTmcsuB9ZzDCo6K6sYEqaEcEnnAFa0zCewAg=
"""
            }
        ]

    def setUp(self):
        self.obj = signify.Signify()

    def test_extraction(self):
        self.assertEquals(
            '\xe3\xb2\xd6\x0e\xca\xa3\xef\x0b\x8c\xad@@\xb2\x04j\xfa\x7f6\xe2\xf9\xe0\t\xf5\x0c-\x14\xd9\xc7\xc2,\xa1%',
            self.obj.extract_raw_public_key(self.KAT[0]['pub']))

        self.assertEquals(
            'D@\xd9\xca\xb2\x96;\xa0^\xbb\x16\xc8\x0f\xf7Y=(hu\x85\xbd\xe4i\xf6\xcf\x0f\xfb#\xc1\xfa\xe0\xa1\xe3\xb2\xd6\x0e\xca\xa3\xef\x0b\x8c\xad@@\xb2\x04j\xfa\x7f6\xe2\xf9\xe0\t\xf5\x0c-\x14\xd9\xc7\xc2,\xa1%',
            self.obj.extract_raw_private_key(self.KAT[0]['priv'], 'test'))

    def test_verify_success(self):
        self.assertTrue(
            self.obj.verify_simple(self.KAT[0]['pub'],
                                   self.KAT[0]['sig'],
                                   self.KAT[0]['message']))

    def test_sign(self):
        sig = self.obj.sign_simple(self.KAT[0]['priv'],
                                   'test',
                                   self.KAT[0]['message'])

        self.assertEquals(self.KAT[0]['sig'], sig)

    def test_decrypt_secret_wrong_password(self):
        self.assertRaises(KeyError,
                          self.obj.sign_simple,
                          self.KAT[0]['priv'],
                          'wrong password',
                          self.KAT[0]['message'])

    def test_verify_failure(self):
        broken_sig = self.KAT[0]['sig'].replace('Malgi', 'Magic')

        self.assertRaises(
            signify.InvalidSignature,
            self.obj.verify_simple, self.KAT[0]['pub'],
                                    broken_sig,
                                    self.KAT[0]['message'])

    def test_generate_sign_no_password(self):
        pub, priv = self.obj.generate('test', None)

        self.assertTrue(pub.startswith('untrusted comment: test public key'))
        self.assertTrue(priv.startswith('untrusted comment: test secret key'))

        sig = self.obj.sign_simple(priv,
                                   None,
                                   'My Message')

        self.assertTrue(
            self.obj.verify_simple(pub,
                                   sig,
                                   'My Message'))

    def test_generate_no_comment(self):
        pub, priv = self.obj.generate(None, None)

        self.assertTrue(pub.startswith('untrusted comment: signify public key'))
        self.assertTrue(priv.startswith('untrusted comment: signify secret key'))

    def test_generate_sign_with_password(self):
        pub, priv = self.obj.generate(None, 'testpassword')

        self.assertTrue(pub.startswith('untrusted comment: signify public key'))
        self.assertTrue(priv.startswith('untrusted comment: signify secret key'))

        sig = self.obj.sign_simple(priv,
                                   'testpassword',
                                   'My Message')

        self.assertTrue(
            self.obj.verify_simple(pub,
                                   sig,
                                   'My Message'))


if __name__ == '__main__':
    unittest.main()
