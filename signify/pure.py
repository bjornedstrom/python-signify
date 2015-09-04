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


class Materialized(object):
    def __init__(self):
        self._blob = None
        self._comment = None
        self._raw = None
        self._keynum = None

    def comment(self):
        return self._comment

    def keynum(self):
        return self._keynum

    def raw(self):
        return self._raw

    def to_bytes(self):
        return self._blob


class Signature(Materialized):
    def __init__(self):
        Materialized.__init__(self)

    def _parse_sigfile(self, msg):
        self._comment, blob = read_message(msg)

        try:
            pkalg, keynum, sig = \
                struct.unpack('!2s8s64s', blob)

            assert pkalg == b'Ed'
        except Exception as e:
            raise SignifyError('malformed signature blob')

        return sig, keynum

    @staticmethod
    def from_bytes(blob):
        assert isinstance(blob, bytes)
        obj = Signature()
        obj._raw, obj._keynum = obj._parse_sigfile(blob)
        obj._blob = blob
        return obj


class PublicKey(Materialized):
    def __init__(self):
        Materialized.__init__(self)

    def _parse_public_key(self, msg):
        self._comment, blob = read_message(msg)

        try:
            pkalg, keynum, pubkey = \
                struct.unpack('!2s8s32s', blob)

            assert pkalg == b'Ed'
        except Exception as e:
            raise SignifyError('malformed public key')

        return pubkey, keynum

    @staticmethod
    def from_bytes(blob):
        assert isinstance(blob, bytes)
        obj = PublicKey()
        obj._blob = blob
        obj._raw, obj._keynum = obj._parse_public_key(blob)
        return obj

    def __repr__(self):
        return '<PublicKey %s>' % (self._keynum.encode('hex'))


class UnprotectedSecretKey(object):
    def __init__(self, sk):
        assert isinstance(sk, SecretKey)
        self._sk = sk
        self._key = None

    def comment(self):
        return self._sk.comment()

    def keynum(self):
        return self._sk.keynum()

    def raw_secret_key(self):
        return self._key


class SecretKey(Materialized):
    def __init__(self):
        Materialized.__init__(self)

    @staticmethod
    def from_bytes(blob):
        assert isinstance(blob, bytes)
        obj = SecretKey()
        obj._blob = blob
        obj._parse_secret_key(blob)
        return obj

    def _parse_secret_key(self, msg):
        comment, blob = read_message(msg)

        try:
            pkalg, kdfalg, kdfrounds, salt, checksum, keynum, seckey = \
                struct.unpack(b'!2s2sL16s8s8s64s', blob)

            assert pkalg == b'Ed'
            assert kdfalg == b'BK'
            assert kdfrounds in [0, 42]
        except Exception as e:
            raise SignifyError(e)

        self._kdfrounds = kdfrounds
        self._salt = salt
        self._checksum = checksum
        self._keynum = keynum
        self._seckey = seckey
        self._comment = comment

    def is_password_protected(self):
        return self._kdfrounds != 0

    def raw(self):
        raise NotImplementedError('call unprotect()')

    def unprotect(self, password):
        if self._kdfrounds == 0:
            xorkey = b'\x00' * 64
        else:
            xorkey = bcrypt.kdf(password, self._salt, 64, self._kdfrounds)
        priv = xorbuf(self._seckey, xorkey)

        checksum_ref = hashlib.sha512(priv).digest()[0:8]
        if self._checksum != checksum_ref:
            raise KeyError('incorrect password')

        usk = UnprotectedSecretKey(self)
        usk._key = priv
        return usk

    def __repr__(self):
        return '<SecretKey %s>' % (self._keynum.encode('hex'))


def sign(secret_key, message, embed=False):
    """Sign a message with the secret key.

    @param secret_key: The secret key to sign the message with.
    @param message: The message to sign.
    @param embed: Whether to create an embedded signature or not.
    """

    assert isinstance(secret_key, UnprotectedSecretKey)
    assert isinstance(message, bytes)

    key_obj = ed25519.keys.SigningKey(secret_key.raw_secret_key())

    sig_buf = key_obj.sign(message)

    sig_blob = b'Ed' + secret_key.keynum() + sig_buf

    sig = write_message('signature from %s' % (secret_key.comment(),), sig_blob)
    if embed:
        sig += message
    return Signature.from_bytes(sig)


def verify(public_key, signature, message):
    """Verify a signature.

    Will return True on success or raise InvalidSignature.

    @param public_key: The public key corresponding to the secret key
    that signed the message.
    @param signature: The signature.
    @param message: The message signed.
    """

    assert isinstance(public_key, PublicKey)
    assert isinstance(signature, Signature)
    assert isinstance(message, bytes)

    key_obj = ed25519.keys.VerifyingKey(public_key.raw())
    try:
        key_obj.verify(signature.raw(), message)
        return True
    except ed25519.BadSignatureError as e:
        raise InvalidSignature('signify: signature verification failed')


def verify_embedded(public_key, embedded_message):
    """Verify an embedded signature.

    See verify() for documentation.
    """

    assert isinstance(public_key, PublicKey)
    assert isinstance(embedded_message, bytes)

    sig1, sig2, message = embedded_message.split(b'\n', 2)
    sig = sig1 + b'\n' + sig2 + b'\n'

    return verify(public_key, Signature.from_bytes(sig), message)


def generate_from_raw(comment, password, raw_pub, raw_priv):
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

    return PublicKey.from_bytes(pub), SecretKey.from_bytes(priv)


def generate(comment, password):
    """Generate a signify keypair.

    @param comment: A comment to name the keypair, or None.
    @param password: A password to protect the private key, or None.
    """
    assert isinstance(comment, (type(None), str, unicode))
    #assert isinstance(password, bytes)

    sk, vk = ed25519.keys.create_keypair()
    return generate_from_raw(comment, password, vk.to_bytes(), sk.to_bytes())


class Signify(object):
    def __init__(self):
        pass

    def is_password_protected(self, priv):
        """Check if the private key is protected with a password."""

        sk = SecretKey.from_bytes(priv)
        return sk.is_password_protected()

    def extract_raw_public_key(self, pubkey):
        """ADVANCED: Given a Signify public key, return the raw ed25519 key.

        This is dangerous and be careful.
        """

        pk = PublicKey.from_bytes(pubkey)
        return pk.raw()

    def extract_raw_private_key(self, privkey, password):
        """ADVANCED: Given a Signify private key, return the raw ed25519 key.

        This is dangerous so be careful.
        """

        sk = SecretKey.from_bytes(privkey)
        sku = sk.unprotect(password)
        return sku.raw_secret_key()

    def generate_from_raw(self, comment, password, raw_pub, raw_priv):
        """ADVANCED: Given a raw Ed25519 key pair raw_pub and raw_priv,
        create a Signify keypair.

        See generate() for documentation.
        """

        pk, sk = generate_from_raw(comment, password, raw_pub, raw_priv)

        return pk.to_bytes(), sk.to_bytes()

    def generate(self, comment, password):
        """Generate a signify keypair.

        @param comment: A comment to name the keypair, or None.
        @param password: A password to protect the private key, or None.
        """

        pk, sk = generate(comment, password)
        return pk.to_bytes(), sk.to_bytes()

    def sign_simple(self, priv, password, message, embed=False):
        """Sign message with the private key.

        @param priv: private key blob
        @param password: The password that protects the private key, or None.
        @param message: The message to be signed.
        """

        sk = SecretKey.from_bytes(priv)
        sku = sk.unprotect(password)
        return sign(sku, message, embed).to_bytes()

    def verify_embedded(self, pubkey, embedded_msg):
        assert isinstance(pubkey, bytes)
        assert isinstance(embedded_msg, bytes)

        pk = PublicKey.from_bytes(pubkey)

        return verify_embedded(pk, embedded_msg)

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

        sig = Signature.from_bytes(sig)
        pk = PublicKey.from_bytes(pubkey)

        return verify(pk, sig, message)
