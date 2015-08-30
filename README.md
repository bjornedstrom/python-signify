# python-signify - Simple Python wrapper around OpenBSD signify(1) command

0.0.0-DEVEL

This is a **work in progress**, fairly simple (subprocess based) wrapper around the OpenBSD signify(1) command. It basically does two things for you to make your life a little bit easier:

- It handles thread safety and the actual calling of subprocess, which is easy to screw up.
- For convenience it will aid you in juggling temporary files in case you want to work with strings/buffers instead of paths, as signify(1) work on paths.

Please make sure you read and understand the library docstrings before you use the code. There are some security considerations.

## Example

```python
from signify import Signify

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

## About

Copyright Björn Edström 2015. See LICENSE for details.
