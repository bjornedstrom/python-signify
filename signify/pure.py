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

        return priv

    def _parse_public_key(self, blob):
        comment, b64 = blob.split('\n', 1)

        buf = base64.b64decode(b64)
        pkalg, keynum, pubkey = \
            struct.unpack('!2s8s32s', buf)

        assert pkalg == 'Ed'

        return pubkey

    def _parse_sigfile(self, blob):
        comment, b64 = blob.split('\n', 1)

        buf = base64.b64decode(b64)
        pkalg, keynum, sig = \
            struct.unpack('!2s8s64s', buf)

        assert pkalg == 'Ed'

        return sig

    #def sign_simple(self, priv, password, message):
    #    privkey = self._decrypt_secret_key(priv, password)
    #    pubkey = ed25519.publickey(privkey)
    #    print [pubkey]
    #    sig = ed25519.signature(message, privkey, pubkey)
    #    print [sig]

    def verify_simple(self, pubkey, sig, message):
        sig_buf = self._parse_sigfile(sig)
        pub_buf = self._parse_public_key(pubkey)
        try:
            ed25519.checkvalid(sig_buf, message, pub_buf)
        except Exception, e:
            raise InvalidSignature('signify: signature verification failed')
        return True
