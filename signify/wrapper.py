# -*- coding: utf-8 -*-
# Copyright (c) Björn Edström <be@bjrn.se> 2015. See LICENSE for details.

import os
import subprocess
import tempfile
import threading


class SignifyError(Exception):
    pass


class InvalidSignature(SignifyError):
    pass


class Signify(object):
    BIN = 'signify'

    def __init__(self):
        """Create an instance of a wrapper around the signify binary.

        This class is thread safe but it's still recommended to only
        have one instance of this class per thread, as that will
        improve performance.
        """

        self._lock = threading.Lock()

    def _generate_from_paths(self, pubkey_path, privkey_path, password=None, comment=None):
        """Use generate()."""

        args = [self.BIN, '-G', '-p', pubkey_path, '-s', privkey_path]
        if comment is not None:
            args += ['-c', comment]
        if not password:
            args += ['-n']

        pobj = subprocess.Popen(args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = pobj.communicate()
        code = pobj.returncode

        if code:
            raise SignifyError(err)

        return True

    def generate(self, pubkey_path, privkey_path, password=None, comment=None):
        """Generate a signify key pair.

        Returns True on success.

        @param pubkey_path: Path to write the public key file.
        @param privkey_path: Path to write the private key file.
        @param password: If false, private key will not be password
        protected. Otherwise it will be protected by a password
        prompted on tty.
        @param comment: A comment.
        """

        with self._lock:
            return self._generate_from_paths(
                pubkey_path, privkey_path, password, comment)

    def generate_unsafe(self, comment, password):
        """Generate a signify key pair.

        Returns (public key, private key) on success.

        @param comment: A comment to name the key pair.
        @param password: If this is unset, the private key will not
        have a password. Otherwise, you will get queried on the tty.

        SECURITY WARNING: The private key will be written as a
        temporary file to a temp directory where it can be read by
        all. This is dangerous if password=None.
        """

        with self._lock:
            # HACK: Get names
            pubkey_fobj = tempfile.NamedTemporaryFile()
            pubkey_fobj.close()
            privkey_fobj = tempfile.NamedTemporaryFile()
            privkey_fobj.close()

            self._generate_from_paths(
                pubkey_fobj.name,
                privkey_fobj.name,
                password,
                comment)

            with open(pubkey_fobj.name, 'rb') as fobj:
                pub = fobj.read()
            with open(privkey_fobj.name, 'rb') as fobj:
                priv = fobj.read()

            os.unlink(pubkey_fobj.name)
            os.unlink(privkey_fobj.name)

            return (pub, priv)

    def _sign_from_paths(self, privkey_path, sig_path, message_path, embed=None):
        # signify -S [-e] [-x sigfile] -s seckey -m message

        args = [self.BIN, '-S', '-s', privkey_path, '-m', message_path, '-x', sig_path]
        if embed:
            args += ['-e']

        pobj = subprocess.Popen(args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = pobj.communicate()
        code = pobj.returncode

        if code:
            raise SignifyError(err)

        return True

    def sign_from_paths(self, privkey_path, sig_path, message_path, embed=None):
        """Perform the signify sign operation.

        This is a low level wrapper around the "signify" binary.

        @param privkey_path: Path to the file that contains the private key.
        @param sig_path: Output: Path to the file that will contain
        the signature.
        @param message_path: Path to the file that contains the data
        to be signed.
        @param embed: If set the output will embed the signature in
        the message. The data will be written to sig_path.
        """

        with self._lock:
            return self._sign_from_paths(privkey_path, sig_path, message_path, embed)

    def sign(self, **kwargs):
        """Perform the signify sign operation.

        Returns the signature on success. Raises an exception on
        error.

        This method takes 3 input named args:

        @param privkey_buf or privkey_path: The private key as either a
        string like buffer, or a path to the file that contains the
        private key.
        @param message_buf or message_path: The message as either a
        string like buffer, or a path to the file that contains the
        message to be signed.
        @param sig_path: If set the signature will be written to this
        file instead of returned.
        @param embed: Optional: If True then the signature will be
        embedded in the message.
        """

        with self._lock:
            privkey_fobj = None
            if 'privkey_buf' in kwargs:
                privkey_fobj = tempfile.NamedTemporaryFile()
                privkey_fobj.write(kwargs['privkey_buf'])
                privkey_fobj.file.flush()

            message_fobj = None
            if 'message_buf' in kwargs:
                message_fobj = tempfile.NamedTemporaryFile()
                message_fobj.write(kwargs['message_buf'])
                message_fobj.file.flush()

            embed = kwargs.get('embed', None)
            output_path = kwargs.get('sig_path', None)

            if output_path is None:
                # HACK: Get names
                sig_fobj = tempfile.NamedTemporaryFile()
                sig_fobj.close()
                output_path = sig_fobj.name

            try:
                self._sign_from_paths(
                    privkey_fobj.name if 'privkey_buf' in kwargs else kwargs['privkey_path'],
                    output_path,
                    message_fobj.name if 'message_buf' in kwargs else kwargs['message_path'],
                    embed)

                if kwargs.get('sig_path', None):
                    return True
                else:
                    with open(sig_fobj.name, 'rb') as fobj:
                        return fobj.read()

            finally:
                if privkey_fobj is not None:
                    privkey_fobj.close()
                if message_fobj is not None:
                    message_fobj.close()

                if not kwargs.get('sig_path', None):
                    os.unlink(output_path)

    def _verify_from_paths(self, pubkey_path, sig_path, message_path):
        """Use verify_from_paths()."""

        pobj = subprocess.Popen(
            [self.BIN, '-V', '-p', pubkey_path, '-m', message_path, '-x', sig_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = pobj.communicate()
        code = pobj.returncode

        if code:
            if b'verification failed' in err:
                raise InvalidSignature(err)
            raise SignifyError(err)

        return True

    def verify_from_paths(self, pubkey_path, sig_path, message_path):
        """Perform the signify verification operation.

        Returns True if the signature is valid otherwise throws an
        exception.

        This is a low level wrapper around the "signify" binary.

        @param pubkey_path: path to the public key file.
        @param sig_path: path to the signature file.
        @param message_patj: path to the message file.
        """

        with self._lock:
            return self._verify_from_paths(pubkey_path, sig_path, message_path)

    def verify_simple(self, pubkey, sig, message):
        """Perform the signify verification operation.

        Returns True if the signature is valid otherwise throws an
        exception.

        This is a convenience wrapper around verify() and makes the
        assumption that all inputs are buffers (such as strings).

        @param pubkey: The public key as a buffer.
        @param sig: The signature as a buffer.
        @param message: The message as a buffer.
        """

        return self.verify(pubkey_buf=pubkey, sig_buf=sig, message_buf=message)

    def verify(self, **kwargs):
        """Perform the signify verification operation.

        Returns True if the signature is valid otherwise throws an
        exception.

        This method takes 3 input named args:

        @param pubkey_buf or pubkey_path: The public key as either a
        string like buffer, or a path to the file that contains the
        public key.
        @param sig_buf or sig_path: The signature as either a string
        like buffer, or a path to the file that contains the
        signature.
        @param message_buf or message_path: The message as either a
        string like buffer, or a path to the file that contains the
        message.

        Example:

        # Verify a huge file called "message.txt"
        verify(pubkey_buf=PUB, sig_buf=SIG, message_path='message.txt')

        # Verify some small blobs (maybe use verify_simple() instead)
        verify(pubkey_buf=PUB, sig_buf=SIG, message_buf=MSG)
        """

        with self._lock:
            pubkey_fobj = None
            if 'pubkey_buf' in kwargs:
                pubkey_fobj = tempfile.NamedTemporaryFile()
                pubkey_fobj.write(kwargs['pubkey_buf'])
                pubkey_fobj.file.flush()

            sig_fobj = None
            if 'sig_buf' in kwargs:
                sig_fobj = tempfile.NamedTemporaryFile()
                sig_fobj.write(kwargs['sig_buf'])
                sig_fobj.file.flush()

            message_fobj = None
            if 'message_buf' in kwargs:
                message_fobj = tempfile.NamedTemporaryFile()
                message_fobj.write(kwargs['message_buf'])
                message_fobj.file.flush()

            try:
                return self._verify_from_paths(
                    pubkey_fobj.name if 'pubkey_buf' in kwargs else kwargs['pubkey_path'],
                    sig_fobj.name if 'sig_buf' in kwargs else kwargs['sig_path'],
                    message_fobj.name if 'message_buf' in kwargs else kwargs['message_path'])
            finally:
                if pubkey_fobj is not None:
                    pubkey_fobj.close()
                if sig_fobj is not None:
                    sig_fobj.close()
                if message_fobj is not None:
                    message_fobj.close()
