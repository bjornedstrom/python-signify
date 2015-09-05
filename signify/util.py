# -*- coding: utf-8 -*-
# Copyright (c) Björn Edström <be@bjrn.se> 2015. See LICENSE for details.

import binascii
import sys


if sys.version_info[0] == 3:
    def xorbuf(buf1, buf2):
        return bytes(x ^ y for x, y in zip(buf1, buf2))

    unicode = str
else:
    def xorbuf(buf1, buf2):
        res = []
        for i in range(len(buf1)):
            res.append(chr(ord(buf1[i]) ^ ord(buf2[i])))
        return ''.join(res)


def bytes2hex(buf):
    return binascii.hexlify(buf).decode('ascii')
