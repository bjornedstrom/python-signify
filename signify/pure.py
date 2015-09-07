# -*- coding: utf-8 -*-
# Copyright (c) Björn Edström <be@bjrn.se> 2015. See LICENSE for details.

"""Signify library

This library provide a few main methods and some minor helpers:

    - sign(...)
    - verify(...)
    - generate(...)

In addition it provide 3 helper classes:

    - PublicKey
    - SecretKey
    - Signature

A signify key/signature is a byte string on the form:
"untrusted comment: ...\\n<base64 blob>\\n"

Use the {PublicKey, SecretKey, Signature}.from_bytes(...) method to
create an object instance from a byte string of the above form. Use
the .to_bytes() method for the opposite direction:

    >>> pubkey = PublicKey.from_bytes(b'''untrusted comment: bjorntest public key
RWQ100QRGZoxU+Oy1g7Ko+8LjK1AQLIEavp/NuL54An1DC0U2cfCLKEl
''')
    >>> print(pubkey.to_bytes())
    b'untrusted...'
    >>> # same goes for Signature and SecretKey

SecretKey:s may be password protected. Use the .unprotect(...) method
to get an UnprotectedSecretKey, which can be used by sign(...).

Example
-------

    pubkey = signify.PublicKey.from_bytes(b'''untrusted comment: bjorntest public key
    RWQ100QRGZoxU+Oy1g7Ko+8LjK1AQLIEavp/NuL54An1DC0U2cfCLKEl
    ''')

    signature = signify.Signature.from_bytes(b'''untrusted comment: signature from bjorntest secret key
    RWQ100QRGZoxU/gjzE8m6GYtfICqE0Ap8SdXRSHrpjnSBKMc2RMalgi5RKrEHmKfTmcsuB9ZzDCo6K6sYEqaEcEnnAFa0zCewAg=
    ''')

    message = b'''my message
    '''

    print(signify.verify(pubkey, signature, message))

    new_pub, new_sec = signify.generate('my new key', 'password')
    new_sig = signify.sign(new_sec.unprotect('password'), message)
    print(new_sig.to_bytes())
    print(signify.verify(new_pub, new_sig, message))

Security Warning
----------------

Python is an interpreted language and there are no guarantees that
your signify secret key, ones unprotected, may end up in swap space or
be recoverable from reading your computers memory.

"""

import base64
import bcrypt
import ed25519
import hashlib
import os
import re
import struct

import signify.check as check
from signify.util import *


class SignifyError(Exception):
    pass


class InvalidSignature(SignifyError):
    pass


class _Materialized(object):
    def __init__(self):
        self._blob = None
        self._comment = None
        self._raw = None
        self._keynum = None

    def comment(self):
        """Returns the plain text comment associated with the object."""
        return self._comment

    def keynum(self):
        """Returns the 8 byte identifier for the object."""
        return self._keynum

    def raw(self):
        return self._raw

    def to_bytes(self):
        """Returns the materialized byte blob for the object."""
        return self._blob

    @staticmethod
    def write_message(comment, blob):
        assert isinstance(comment, (str, unicode))
        assert isinstance(blob, bytes)
        return b'untrusted comment: ' + comment.encode('utf-8') + b'\n' + base64.b64encode(blob) + b'\n'

    @staticmethod
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


class Signature(_Materialized):
    """A Signature object."""

    def __init__(self):
        _Materialized.__init__(self)

    def _parse_sigfile(self, msg):
        self._comment, blob = _Materialized.read_message(msg)

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

    def __repr__(self):
        return '<Signature by %s>' % (bytes2hex(self._keynum))


class PublicKey(_Materialized):
    """A Signify public key."""

    def __init__(self):
        _Materialized.__init__(self)

    def _parse_public_key(self, msg):
        self._comment, blob = _Materialized.read_message(msg)

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
        return '<PublicKey %s>' % (bytes2hex(self._keynum))


class UnprotectedSecretKey(object):
    """This class represents a decrypted secret key that can be used for
    signing operations."""

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


class SecretKey(_Materialized):
    """A Signify secret key object."""

    def __init__(self):
        _Materialized.__init__(self)

    @staticmethod
    def from_bytes(blob):
        assert isinstance(blob, bytes)
        obj = SecretKey()
        obj._blob = blob
        obj._parse_secret_key(blob)
        return obj

    def _parse_secret_key(self, msg):
        comment, blob = _Materialized.read_message(msg)

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
        """Returns True if this secret key is protected with a password."""

        return self._kdfrounds != 0

    def raw(self):
        raise NotImplementedError('call unprotect()')

    def unprotect(self, password):
        """Decrypt the SecretKey object and return an UnprotectedSecretKey
        that can be used for signing.

        Can throw KeyError if the password is incorrect.
        """

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
        return '<SecretKey %s>' % (bytes2hex(self._keynum))


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

    sig = _Materialized.write_message('signature from %s' % (secret_key.comment(),), sig_blob)
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

    If the signature verification fails, raise InvalidSignature.

    Otherwise, it will return the message embedded in the signature.

    @param public_key: The public key corresponding to the secret key
    that signed the message.
    @param embedded_message: The message(bytes) or Signature.
    """

    assert isinstance(public_key, PublicKey)
    assert isinstance(embedded_message, (bytes, Signature))

    if isinstance(embedded_message, Signature):
        embedded_message = embedded_message.to_bytes()

    sig1, sig2, message = embedded_message.split(b'\n', 2)
    sig = sig1 + b'\n' + sig2 + b'\n'

    verify(public_key, Signature.from_bytes(sig), message)

    return message


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
    priv = _Materialized.write_message('%s secret key' % (comment,), priv_blob)

    # public key
    pub_blob = b'Ed' + keynum + raw_pub
    pub = _Materialized.write_message('%s public key' % (comment,), pub_blob)

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


def sign_files(secret_key, algo, paths, root='.'):
    """Make an embedded signature containing files and file hashes.

    This is equivlant to signing the output of `sha256sum --tag` (or
    `sha512sum`) and is provided here for portability.

    @param secret_key: The secret key to sign with.
    @param algo: Either the string 'SHA256' or 'SHA512'.
    @param paths: A list of paths to hash and sign.
    @param root: The root directory `paths` are relative from.
    """

    msg = check.openbsd_sha_files(algo, root, paths).encode('utf-8')
    return sign(secret_key, msg, embed=True)


def verify_files(public_key, signature, root='.'):
    """Verify the output of sign_files().

    Raise InvalidSignature on error.

    Returns a list of (path, status) tuples where status is True if
    checksum matches, otherwise False if verification fails, or an
    Exception instance (if for example the file can't be opened).

    @param public_key: The public key to check against.
    @param signature: The embedded signature containing the hashes.
    @param root: The directory of which the paths in the signature are
    relative against.
    """

    checkfile = verify_embedded(public_key, signature)

    return list(check.checkfiles(root, checkfile.decode('utf-8')))
