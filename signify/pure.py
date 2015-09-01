# -*- coding: utf-8 -*-
# Copyright (c) Björn Edström <be@bjrn.se> 2015. See LICENSE for details.

# WORK IN PROGRESS

import base64
import bcrypt
import ed25519
import hashlib
import os
import struct


class SignifyError(Exception):
    pass


class InvalidSignature(SignifyError):
    pass


def xorbuf(buf1, buf2):
    res = []
    for i in range(len(buf1)):
        res.append(chr(ord(buf1[i]) ^ ord(buf2[i])))
    return ''.join(res)


class Signify(object):
    def __init__(self):
        pass

    def _decrypt_secret_key(self, blob, password):
        comment, b64 = blob.split('\n', 1)

        buf = base64.b64decode(b64)
        pkalg, kdfalg, kdfrounds, salt, checksum, keynum, seckey = \
            struct.unpack('!2s2sL16s8s8s64s', buf)

        assert pkalg == 'Ed'
        assert kdfalg == 'BK'
        assert kdfrounds == 42

        xorkey = bcrypt.kdf(password, salt, 64, kdfrounds)
        priv = xorbuf(seckey, xorkey)

        checksum_ref = hashlib.sha512(priv).digest()[0:8]
        if checksum != checksum_ref:
            raise KeyError('incorrect password')

        return priv, keynum

    def _parse_public_key(self, blob):
        comment, b64 = blob.split('\n', 1)

        buf = base64.b64decode(b64)
        pkalg, keynum, pubkey = \
            struct.unpack('!2s8s32s', buf)

        assert pkalg == 'Ed'

        return pubkey, keynum

    def _parse_sigfile(self, blob):
        comment, b64 = blob.split('\n', 1)

        buf = base64.b64decode(b64)
        pkalg, keynum, sig = \
            struct.unpack('!2s8s64s', buf)

        assert pkalg == 'Ed'

        return sig, keynum

    def sign_simple(self, priv, password, message):
        priv_buf, priv_keynum = self._decrypt_secret_key(priv, password)
        key_obj = ed25519.keys.SigningKey(priv_buf)

        sig_buf = key_obj.sign(message)

        return 'untrusted comment: signature from TODO secret key\n' + \
            base64.b64encode('Ed' + priv_keynum + sig_buf)

    def verify_simple(self, pubkey, sig, message):
        sig_buf, sig_keynum = self._parse_sigfile(sig)
        pub_buf, pub_keynum = self._parse_public_key(pubkey)

        key_obj = ed25519.keys.VerifyingKey(pub_buf)
        try:
            key_obj.verify(sig_buf, message)
            return True
        except ed25519.BadSignatureError, e:
            raise InvalidSignature('signify: signature verification failed')
