# python-signify - OpenBSD Signify for Python

0.0.0-DEVEL

[Signify](http://www.tedunangst.com/flak/post/signify) was originally written for OpenBSD to sign files and packages. This projects contains some code for working with signify keys/signatures from Python.

Specifically this project contains two modules: one that uses the `subprocess` module and one that simply re-implements Signify functionality directly. There is also a driver program using the library: `signi.py`, which is similar to the normal signify program.

## Module 1: "Pure" Python version

The `signify.pure` module has a Python implementation of some parts of `signify`, without requiring the signify binary or the subprocess module. This code requires the Python bcrypt and ed25519 modules.

### Dependencies

- [python-ed25519](https://github.com/warner/python-ed25519]) (`pip install ed25519`)
- [py-bcrypt](py-bcrypt) (`pip install py-bcrypt`)

### Example (Python 2)

```python
from signify.pure import Signify

pubkey = """untrusted comment: bjorntest public key
RWQ100QRGZoxU+Oy1g7Ko+8LjK1AQLIEavp/NuL54An1DC0U2cfCLKEl
"""

signature = """untrusted comment: signature from bjorntest secret key
RWQ100QRGZoxU/gjzE8m6GYtfICqE0Ap8SdXRSHrpjnSBKMc2RMalgi5RKrEHmKfTmcsuB9ZzDCo6K6sYEqaEcEnnAFa0zCewAg=
"""

message = """my message
"""

print Signify().verify_simple(pubkey, signature, message)
broken_sig = signature.replace('Malgi', 'Magic')
print Signify().verify_simple(pubkey, broken_sig, message)
```

## Module 2: Subprocess based wrapper around signify(1)

This is a fairly simple (subprocess based) wrapper around the OpenBSD signify(1) command. It basically does two things for you to make your life a little bit easier:

- It handles thread safety and the actual calling of subprocess, which is easy to screw up.
- For convenience it will aid you in juggling temporary files in case you want to work with strings/buffers instead of paths, as signify(1) work on paths.

Please make sure you read and understand the library docstrings before you use the code. There are some security considerations.

### Example

The API is sort of similar to the one above.

## Driver Program

Work in progress:

    $ signi.py -h
    usage:
        signi.py -G [-n] [-c comment] -p pubkey -s seckey
        signi.py -S [-e] [-x sigfile] -s seckey -m message
        signi.py -V [-eq] [-x sigfile] -p pubkey -m message

## About

Copyright Björn Edström 2015. See LICENSE for details.
