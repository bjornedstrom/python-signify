# -*- coding: utf-8 -*-
# Copyright (c) Björn Edström <be@bjrn.se> 2015. See LICENSE for details.

import hashlib
import re
import os

BUFSIZE = 64*1024
ALGO_TO_CLS = {
    'SHA256': hashlib.sha256,
    'SHA512': hashlib.sha512,
}


def hash_file(hashobj, path):
    with open(path, 'rb') as fobj:
        while True:
            buf = fobj.read(BUFSIZE)
            hashobj.update(buf)
            if buf != BUFSIZE:
                break
    return True


def openbsd_sha_files(algo_str, root, files):
    hash_cls = ALGO_TO_CLS[algo_str]
    res = []
    for path in files:
        hashobj = hash_cls()
        hash_file(hashobj, os.path.join(root, path))
        res.append('%s (%s) = %s' % (algo_str, path, hashobj.hexdigest()))
    return '\n'.join(res)


def checkfiles(root, checkfile):
    for algo, path, ref_digest in re.findall(
            r'^(\S+) [(]([^)]+)[)] = ([0-9a-fA-F]+)$', checkfile, re.M):
        hash_cls = ALGO_TO_CLS[algo]
        hashobj = hash_cls()
        hash_file(hashobj, os.path.join(root, path))
        digest = hashobj.hexdigest()
        status = digest.upper() == ref_digest.upper()
        yield (path, status)
