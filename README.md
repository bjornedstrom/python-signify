# python-signify - OpenBSD Signify for Python

0.1.0-RC1

[![Build Status](https://travis-ci.org/bjornedstrom/python-signify.png?branch=master)](https://travis-ci.org/bjornedstrom/python-signify)

[Signify](http://www.tedunangst.com/flak/post/signify) was originally written for OpenBSD to sign files and packages, as a light-weight replacement for using PGP. python-signify is a module for working with Signify keys/signatures from Python. The module allow you to sign/verify messages and work with Signify keypairs.

Specifically this project contains two modules that you can use depending on requirements: the first one re-implements Signify functionality directly, and is the recommended use of python-signify. The second one uses the `subprocess` module and use the `signify` binary.

There is also a driver program using the library: `signi.py`, which is similar to the normal signify program in behavior.

## Installation

python-signify is tested on a few versions of Python 2 and 3.

The `signify.pure` module has a Python implementation of some parts of Signify, without requiring the `signify` binary. This module has two dependencies:

- [python-ed25519](https://github.com/warner/python-ed25519]) (`pip install ed25519`)
- [py-bcrypt](py-bcrypt) (`pip install py-bcrypt`)

If you use the `subprocess` based module, then there are no dependencies other than that `signify` is installed  on the system and reachable on PATH.

## Usage

Signify keys and signatures are `b'python bytestrings'` that start with the string `b'untrusted comment:'`. From this representation, you can create a `PublicKey`, `SecretKey` and `Signature` object using the `.from_bytes()` method, as shown in the example below (the opposite direction is called `.to_bytes()`):

### API Example (tl;dr)

```python
import signify.pure as signify

pubkey = signify.PublicKey.from_bytes(b"""untrusted comment: bjorntest public key
RWQ100QRGZoxU+Oy1g7Ko+8LjK1AQLIEavp/NuL54An1DC0U2cfCLKEl
""")

signature = signify.Signature.from_bytes(b"""untrusted comment: signature from bjorntest secret key
RWQ100QRGZoxU/gjzE8m6GYtfICqE0Ap8SdXRSHrpjnSBKMc2RMalgi5RKrEHmKfTmcsuB9ZzDCo6K6sYEqaEcEnnAFa0zCewAg=
""")

message = b"""my message
"""

print(signify.verify(pubkey, signature, message))

new_pub, new_sec = signify.generate('my new key', 'password')
new_sig = signify.sign(new_sec.unprotect('password'), message)
print(new_sig.to_bytes())
print(signify.verify(new_pub, new_sig, message))
```

### Secret Keys and Signing

Before you can use a `SecretKey` for the signing operation, you have to decrypt it using the `SecretKey.unprotect()` method. A normal pattern is as follows:

```python
from signify.pure import SecretKey, sign
sk = SecretKey.from_bytes(...)
sku = sk.unprotect('password')
sig = sign(sku, b'my message')
print(sig.to_bytes())
```

### Public Keys and Verifying

The `verify` function takes a public key, a signature and the bytestring that was signed. `InvalidSignature` will be raised on invalid signatures.

```python
from signify.pure import PublicKey, Signature, verify
pk = PublicKey.from_bytes(...)
sig = Signature.from_bytes(...)
print(verify(pk, sig, b'my message'))
```

### Generating a New Keypair

If you do not already have a Signify keypair (`signify -G`) you can generate one as follows:

```python
from signify.pure import generate
pk, sk = generate('alice aliceson', 'password')
```

The first parameter is a comment describing the key.

### Embedded Signatures

An "embedded signature" is the concatenation of a signature and the message signed. An embedded signature looks like this:

    untrusted comment: signature from signify secret key
    RWQwAARFerRo1COfT3i7SkSrTjDImrhchgmiX2Vbmy9LZdRM6j...
    Here is my signed message!

Signing and verifying embedded signatures works as follows:

```python
from signify.pure import PublicKey, SecretKey, sign, verify_embedded

# Sign
sk = SecretKey.from_bytes(...)
sku = sk.unprotect('password')
sig = sign(sku, b'my message', embed=True)
print(sig.to_bytes())

# Verify
pk = PublicKey.from_bytes(...)
embedded_signature = Signature.from_bytes(<embedded signature>)
print(verify_embedded(pk, embedded_signature))
```

### Signing Files

A common Signify use case is to sign one or more files, such as source code distributions. The Signify convention as used in OpenBSD is to make an embedded signature (see above) of the output of OpenBSD `sha256(1)` or Linux `sha256sum --tag` (SHA512 is also common). These looks like this:

    untrusted comment: signature from signify secret key
    RWQwAARFerRo1COfT3i7SkSrTjDImrhchgmiX2Vbmy9LZdRM6jJhzMQZFLlZKKEOiEcbLAtzpvJ0TT4dqYYfClpoUfoTnnF4sgM=
    SHA256 (bjorn.pub) = a829d2df993afa575607d77ca4f1a813d9486f07f45b826386c337a2d712d721
    SHA256 (bjorn.sec) = b4b8b2d99549fa2c67848e1f6e091a3ea0696c6106755299a7424940524552c0

You sign and verify these as follows:

```python
import os
from signify.pure import PublicKey, SecretKey, sign_files

# Sign
sk = SecretKey.from_bytes(...)
sku = sk.unprotect('password')
paths = ['bjorn.pub', 'bjorn.sec']
sig = sign_files(sku, 'SHA256', paths, root=os.getcwd())

# Verify
TODO
```

## Extras

### Subprocess based wrapper around signify(1)

`signify.wrapper` is a fairly simple (subprocess based) wrapper around the OpenBSD signify(1) command. It basically does two things for you to make your life a little bit easier:

- It handles thread safety and the actual calling of subprocess, which is easy to screw up.
- For convenience it will aid you in juggling temporary files in case you want to work with strings/buffers instead of paths, as signify(1) work on paths.

Please make sure you read and understand the library docstrings before you use the code. There are some security considerations.

The wrapper API is a little bit different from the pure API. Please consult the docstrings for more information.

### Driver Program

Work in progress:

    $ signi.py -h
    usage:
        signi.py -G [-n] [-c comment] -p pubkey -s seckey
        signi.py -S [-e] [-x sigfile] -s seckey -m message
        signi.py -V [-eq] [-x sigfile] -p pubkey -m message

## About

Copyright Björn Edström 2015. See LICENSE for details.
