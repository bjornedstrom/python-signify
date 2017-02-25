# python-signify - OpenBSD Signify for Python

0.1.0-RC1

[![Build Status](https://travis-ci.org/bjornedstrom/python-signify.png?branch=master)](https://travis-ci.org/bjornedstrom/python-signify)

[Signify](http://www.tedunangst.com/flak/post/signify) was originally written for OpenBSD to sign files and packages, as a light-weight replacement to using PGP. **python-signify** is a module for working with Signify keys/signatures from Python. This module allow you to sign/verify messages and work with Signify keypairs.

Specifically this project contains two modules that you can use depending on requirements: the first one re-implements Signify functionality directly, and is the recommended use of python-signify. The second one uses the `subprocess` module and use the `signify` binary.

There is also a driver program using the library: `signipie`, which offer some additional convenience over the reference `signify` implementation.

#### Security Warning

Obligatory security warning for Python projects using cryptographic keys: python-signify makes **no** attempts to guard your secret keys against memory based attacks. If you use python-signify you realize that your secret keys may end up in swap space, or in computer RAM longer than necessary. If this is a problem for you, do not use python-signify.

## Installation

python-signify is tested on a few versions of Python 2 and 3.

The `signify.pure` module has a Python implementation of some parts of Signify, without requiring the `signify` binary. This module has two dependencies:

- [python-ed25519](https://github.com/warner/python-ed25519) (`pip install ed25519`)
- [py-bcrypt](https://github.com/pyca/bcrypt) (`pip install py-bcrypt`)

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

### Signing and Verifying Multiple Files

A common Signify use case is to sign one or more files, such as source code distributions. The Signify convention as used in OpenBSD is to make an embedded signature (see above) of the output of OpenBSD `sha256(1)` or Linux `sha256sum --tag` (SHA512 is also common). These looks like this:

    untrusted comment: signature from signify secret key
    RWQwAARFerRo1COfT3i7SkSrTjDImrhchgmiX2Vbmy9LZdRM6jJhzMQZFLlZKKEOiEcbLAtzpvJ0TT4dqYYfClpoUfoTnnF4sgM=
    SHA256 (bjorn.pub) = a829d2df993afa575607d77ca4f1a813d9486f07f45b826386c337a2d712d721
    SHA256 (bjorn.sec) = b4b8b2d99549fa2c67848e1f6e091a3ea0696c6106755299a7424940524552c0

You sign and verify these as follows:

```python
import os
from signify.pure import PublicKey, SecretKey, Signature, sign_files, verify_files

# Sign
sk = SecretKey.from_bytes(...)
sku = sk.unprotect('password')
paths = ['bjorn.pub', 'bjorn.sec']
sig = sign_files(sku, 'SHA256', paths, root=os.getcwd())

# Verify
pk = PublicKey.from_bytes(...)
sig = Signature.from_bytes(...)
print(verify_files(pk, sig, root=os.getcwd()))
```

## Signipie

`signipie` is a command line program that is similar to `signify` but is written to be slightly more user friendly. It has the same basic functionality as `signify` but with some additional convenience helpers around key management and command line parsing.

### Signipie Key Management

Signipie will look for your key-pair(s) in `~/.signify`, where the default key-pair is `~/.signify/id_$USER` and `~/.signify/id_$USER.pub` for the secret and public key, respectively. In addition, it will look for your trusted public keys in `~/.signify/trusted/`. If you have copies of your keys in these directories, then `signipie` can be invoked without specifying key search directories.

If you have multiple Signify key-pairs, then they can be given an id instead of you having to type out full path names to the keys each time. An id is simply a name or label given to your keys. For example, the two keys `~/.signify/id_alice` and `~/.signify/id_alice.pub` collectively have the id `id_alice`.

Of course, `signipie` can be invoked with explicit keys, similar to `signify`, if that is desired.

### Signing and Verifying with Signipie

Once your file system is set up according to the layout above, you can sign and verify messages simply as follows:

    $ signipie sign my-file
    $ cat my-file.sig
	$ signipie verify -x my-file.sig my-file
	Signature Verified (key: id_bjorn.pub)

To make an embedded signature, simply add an `-e`:

    $ signipie sign -e my-file
	$ cat my-file.sig
	$ signipie verify -e -x my-file.sig

To sign multiple files:

    $ signipie sign -c bjorn.pub bjorn.sec > bjorn-files
	$ cat bjorn-files
	$ signipie verify -c -x bjorn-files

## Extras

### Subprocess based wrapper around signify(1)

`signify.wrapper` is a fairly simple (subprocess based) wrapper around the OpenBSD signify(1) command. It basically does two things for you to make your life a little bit easier:

- It handles thread safety and the actual calling of subprocess, which is easy to screw up.
- For convenience it will aid you in juggling temporary files in case you want to work with strings/buffers instead of paths, as signify(1) work on paths.

Please make sure you read and understand the library docstrings before you use the code. There are some security considerations.

The wrapper API is a little bit different from the pure API. Please consult the docstrings for more information.

### `signi.py` - Reference Driver Program

`signi.py` has similar behavior as the normal `signify` program and is included for convenience.

    $ signi.py -h
    usage:
        signi.py -C [-q] -p pubkey -x sigfile [file ...]
        signi.py -F -s seckey -x sigfile [file ...]
        signi.py -G [-n] [-c comment] -p pubkey -s seckey
        signi.py -S [-e] [-x sigfile] -s seckey -m message
        signi.py -V [-eq] [-x sigfile] -p pubkey -m message

- `-G` generates a new keypair.
- `-S` and `-V` signs and generates an arbitrary message, respectively.
- `-F` and `-C` signs and checks files, respectively (see the "Sign Files" section above for more information).

`signi.py -F` option is not included in the normal `signify` binary but is included for convenience.

## About

Copyright Björn Edström 2015. See LICENSE for details.
