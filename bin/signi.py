#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) Björn Edström <be@bjrn.se> 2015. See LICENSE for details.

import argparse
import getpass
import signify.pure as signify


def one(*args):
    return 1 == len(list(arg for arg in args if arg))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-V', '--verify', action='store_true', help='verify')
    parser.add_argument('-S', '--sign', action='store_true', help='sign')
    parser.add_argument('-G', '--generate', action='store_true', help='generate')

    parser.add_argument('-p', '--pubkey', help='pubkey')
    parser.add_argument('-s', '--seckey', help='seckey')
    parser.add_argument('-m', '--message', help='message')
    parser.add_argument('-x', '--signature', help='message')

    parser.add_argument('-n', '--nopass', action='store_true', help='nopass')
    parser.add_argument('-c', '--comment', help='comment')
    args = parser.parse_args()

    if not one(args.verify, args.sign, args.generate):
        parser.error('only one of -V, -S, -G can be given at the same time')

    if args.verify:
        raise NotImplementedError('verify')
    elif args.sign:
        if not (args.seckey and args.message):
            parser.error('-S require -s and -m')
        with open(args.seckey) as fobj:
            seckey = fobj.read()

        # TODO: Check if the key needs a password
        password1 = getpass.getpass()
        if password1 == '':
            password1 = None

        with open(args.message) as fobj:
            message = fobj.read()
            sig = signify.Signify().sign_simple(seckey, password1, message)

        output_filename = args.message + '.sig'
        if args.signature:
            output_filename = args.signature

        with file(output_filename, 'w') as fobj:
            fobj.write(sig)
    elif args.generate:
        if not (args.pubkey and args.seckey):
            parser.error('-G require -p and -s')
        if args.pubkey == args.seckey:
            parser.error('need distinct names for -p and -s')
        if args.nopass:
            password1 = None
        else:
            password1 = getpass.getpass('Password: ')
            password2 = getpass.getpass('Password again: ')
            if password1 != password2:
                parser.error('passwords do not match')

        pub, priv = signify.Signify().generate(args.comment, password1)
        with open(args.pubkey, 'w') as fobj:
            fobj.write(pub)
        with open(args.seckey, 'w') as fobj:
            fobj.write(priv)


if __name__ == '__main__':
    main()
