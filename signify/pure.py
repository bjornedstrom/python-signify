# -*- coding: utf-8 -*-
# Copyright (c) Björn Edström <be@bjrn.se> 2015. See LICENSE for details.

# WORK IN PROGRESS

import base64
import bcrypt
import ed25519
import hashlib
import os
import re
import struct
import sys


class SignifyError(Exception):
    pass


class InvalidSignature(SignifyError):
    pass


if sys.version_info.major == 3:
    def xorbuf(buf1, buf2):
        return bytes(x ^ y for x, y in zip(buf1, buf2))

    unicode = str
else:
    def xorbuf(buf1, buf2):
        res = []
        for i in range(len(buf1)):
            res.append(chr(ord(buf1[i]) ^ ord(buf2[i])))
        return ''.join(res)


def write_message(comment, blob):
    assert isinstance(comment, (str, unicode))
    assert isinstance(blob, bytes)
    return b'untrusted comment: ' + comment.encode('utf-8') + b'\n' + base64.b64encode(blob) + b'\n'


def read_message(msg):
    assert isinstance(msg, bytes)

    try:
        comment_line, b64 = msg.split(b'\n', 1)
    except:
        raise SignifyError('malformed message')

    try:
        blob = base64.b64decode(b64)
    except:
        raise SignifyError('malformed message: base64 error')

    try:
        comment = re.findall(r'^untrusted comment: (.*?)$', comment_line.decode('utf-8'))[0]
    except:
        raise SignifyError('malformed message: expected a comment line')

    return (comment, bytes(blob))


class Signify(object):
    def __init__(self):
        pass

    def _decrypt_secret_key(self, msg, password):
        comment, blob = read_message(msg)

        try:
            pkalg, kdfalg, kdfrounds, salt, checksum, keynum, seckey = \
                struct.unpack(b'!2s2sL16s8s8s64s', blob)

            assert pkalg == b'Ed'
            assert kdfalg == b'BK'
            assert kdfrounds in [0, 42]
        except Exception as e:
            raise SignifyError(e)

        if kdfrounds == 0:
            xorkey = b'\x00' * 64
        else:
            xorkey = bcrypt.kdf(password, salt, 64, kdfrounds)
        priv = xorbuf(seckey, xorkey)

        checksum_ref = hashlib.sha512(priv).digest()[0:8]
        if checksum != checksum_ref:
            raise KeyError('incorrect password')

        return priv, keynum, comment

    def _parse_public_key(self, msg):
        comment, blob = read_message(msg)

        try:
            pkalg, keynum, pubkey = \
                struct.unpack('!2s8s32s', blob)

            assert pkalg == b'Ed'
        except Exception as e:
            raise SignifyError('malformed public key')

        return pubkey, keynum

    def _parse_sigfile(self, msg):
        comment, blob = read_message(msg)

        try:
            pkalg, keynum, sig = \
                struct.unpack('!2s8s64s', blob)

            assert pkalg == b'Ed'
        except Exception as e:
            raise SignifyError('malformed signature blob')

        return sig, keynum

    def is_password_protected(self, priv):
        """Check if the private key is protected with a password."""

        assert isinstance(priv, bytes)

        comment, blob = read_message(priv)

        try:
            pkalg, kdfalg, kdfrounds = \
                struct.unpack(b'!2s2sL', blob[0:8])

            assert pkalg == b'Ed'
            assert kdfalg == b'BK'
            return kdfrounds != 0
        except Exception as e:
            raise SignifyError(e)

    def extract_raw_public_key(self, pubkey):
        """ADVANCED: Given a Signify public key, return the raw ed25519 key.

        This is dangerous and be careful.
        """

        assert isinstance(pubkey, bytes)

        key, keynum = self._parse_public_key(pubkey)
        return key

    def extract_raw_private_key(self, privkey, password):
        """ADVANCED: Given a Signify private key, return the raw ed25519 key.

        This is dangerous so be careful.
        """

        priv_buf, priv_keynum, comment = self._decrypt_secret_key(privkey, password)
        return priv_buf

    def generate_from_raw(self, comment, password, raw_pub, raw_priv):
        """ADVANCED: Given a raw Ed25519 key pair raw_pub and raw_priv,
        create a Signify keypair.

        See generate() for documentation.
        """

        assert isinstance(raw_pub, bytes)
        assert isinstance(raw_priv, bytes)

        if comment is None:
            comment = 'signify'

        keynum = os.urandom(8)

        # private key
        kdfrounds = 42
        salt = os.urandom(16)

        if password is None:
            kdfrounds = 0
            xorkey = b'\x00' * 64
        else:
            xorkey = bcrypt.kdf(password, salt, 64, kdfrounds)
        protected_key = xorbuf(xorkey, raw_priv)
        checksum = hashlib.sha512(raw_priv).digest()[0:8]

        priv_blob = b'Ed' + b'BK' + struct.pack('!L', kdfrounds) + \
                    salt + checksum + keynum + protected_key
        priv = write_message('%s secret key' % (comment,), priv_blob)

        # public key
        pub_blob = b'Ed' + keynum + raw_pub
        pub = write_message('%s public key' % (comment,), pub_blob)

        return pub, priv

    def generate(self, comment, password):
        """Generate a signify keypair.

        @param comment: A comment to name the keypair, or None.
        @param password: A password to protect the private key, or None.
        """
        assert isinstance(comment, (type(None), str, unicode))
        #assert isinstance(password, bytes)

        sk, vk = ed25519.keys.create_keypair()
        return self.generate_from_raw(comment, password, vk.to_bytes(), sk.to_bytes())

    def sign_simple(self, priv, password, message, embed=False):
        """Sign message with the private key.

        @param priv: private key blob
        @param password: The password that protects the private key, or None.
        @param message: The message to be signed.
        """

        assert isinstance(priv, bytes)
        assert isinstance(message, bytes)

        priv_buf, priv_keynum, comment = self._decrypt_secret_key(priv, password)
        key_obj = ed25519.keys.SigningKey(priv_buf)

        sig_buf = key_obj.sign(message)

        sig_blob = b'Ed' + priv_keynum + sig_buf

        sig = write_message('signature from %s' % (comment,), sig_blob)
        if embed:
            sig += message
        return sig

    def verify_embedded(self, pubkey, embedded_sig):
        assert isinstance(pubkey, bytes)
        assert isinstance(embedded_sig, bytes)

        sig1, sig2, message = embedded_sig.split(b'\n', 2)
        sig = sig1 + b'\n' + sig2 + b'\n'

        return self.verify_simple(pubkey, sig, message)

    def verify_simple(self, pubkey, sig, message):
        """Perform signature verification.

        throws InvalidSignature on error.

        @param pubkey: The public key to verify against.
        @param sig: The signature blob.
        @param message: The message that was signed.
        """

        assert isinstance(pubkey, bytes)
        assert isinstance(sig, bytes)
        assert isinstance(message, bytes)

        sig_buf, sig_keynum = self._parse_sigfile(sig)
        pub_buf, pub_keynum = self._parse_public_key(pubkey)

        key_obj = ed25519.keys.VerifyingKey(pub_buf)
        try:
            key_obj.verify(sig_buf, message)
            return True
        except ed25519.BadSignatureError as e:
            raise InvalidSignature('signify: signature verification failed')
