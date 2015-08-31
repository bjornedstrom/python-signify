# -*- coding: utf-8 -*-
# Copyright (C) 2015 Björn Edström <be@bjrn.se>

import signify
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

    def test_verify_success(self):
        self.assertTrue(
            self.obj.verify_simple(self.KAT[0]['pub'],
                                   self.KAT[0]['sig'],
                                   self.KAT[0]['message']))

    def test_verify_failure(self):
        broken_sig = self.KAT[0]['sig'].replace('Malgi', 'Magic')

        self.assertRaises(
            signify.InvalidSignature,
            self.obj.verify_simple, self.KAT[0]['pub'],
                                    broken_sig,
                                    self.KAT[0]['message'])

    def test_generate(self):
        pub, priv = self.obj.generate_unsafe('test', None)

    def test_sign(self):
        pub, priv = self.obj.generate_unsafe('test', None)

        sig = self.obj.sign(privkey_buf=priv,
                            message_buf='My Message')

        self.assertTrue(
            self.obj.verify_simple(pub,
                                   sig,
                                   'My Message'))

if __name__ == '__main__':
    unittest.main()
