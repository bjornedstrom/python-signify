#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) Björn Edström <be@bjrn.se> 2015. See LICENSE for details.

import argparse
import getpass
import sys
import signify.pure as signify


def main():
    parser = argparse.ArgumentParser(usage="""
    %(prog)s -C [-q] -p pubkey -x sigfile [file ...]
    %(prog)s -G [-n] [-c comment] -p pubkey -s seckey
    %(prog)s -S [-e] [-x sigfile] -s seckey -m message
    %(prog)s -V [-eq] [-x sigfile] -p pubkey -m message""")

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('-V', '--verify', action='store_true', help='verify')
    action_group.add_argument('-S', '--sign', action='store_true', help='sign')
    action_group.add_argument('-G', '--generate', action='store_true', help='generate')
    action_group.add_argument('-C', '--check', action='store_true', help='check signed openbsd sha256(1)')

    parser.add_argument('-p', '--pubkey', help='pubkey file')
    parser.add_argument('-s', '--seckey', help='seckey file')
    parser.add_argument('-m', '--message', help='message file')
    parser.add_argument('-x', '--signature', help='signature file')

    misc_group = parser.add_argument_group('misc')
    misc_group.add_argument('-e', '--embed', action='store_true', help='embed signature')
    misc_group.add_argument('-q', '--quiet', action='store_true', help='quiet mode')

    misc_group.add_argument('-n', '--nopass', action='store_true', help='do not password protect')
    misc_group.add_argument('-c', '--comment', help='comment')
    args = parser.parse_args()

    if args.verify:
        if not (args.pubkey and args.message):
            parser.error('-V require -p and -m')
        with open(args.pubkey, 'rb') as fobj:
            pubkey = fobj.read()

        if args.embed:
            if args.signature:
                parser.error('-e and -x are mutually exclusive')

            sig = None
        else:
            sig_filename = args.message + '.sig'
            if args.signature:
                sig_filename = args.signature

            with open(sig_filename, 'rb') as fobj:
                sig = fobj.read()

        with open(args.message, 'rb') as fobj:
            message = fobj.read()

        try:
            if args.embed:
                signify.Signify().verify_embedded(pubkey, message)
            else:
                signify.Signify().verify_simple(pubkey, sig, message)
            if not args.quiet:
                print('Signature Verified')
        except signify.InvalidSignature as e:
            if not args.quiet:
                print('signify: verification failed')
            sys.exit(1)

    elif args.check:
        raise NotImplementedError('-C is the least portable signify option since it assumes OpenBSD sha256(1) output')

    elif args.sign:
        if not (args.seckey and args.message):
            parser.error('-S require -s and -m')
        with open(args.seckey, 'rb') as fobj:
            seckey = fobj.read()

        if signify.Signify().is_password_protected(seckey):
            password1 = getpass.getpass()
        else:
            password1 = None

        with open(args.message, 'rb') as fobj:
            message = fobj.read()
            sig = signify.Signify().sign_simple(seckey, password1, message)

        output_filename = args.message + '.sig'
        if args.signature:
            output_filename = args.signature

        with open(output_filename, 'wb') as fobj:
            fobj.write(sig)
            if args.embed:
                fobj.write(message)

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
        with open(args.pubkey, 'wb') as fobj:
            fobj.write(pub)
        with open(args.seckey, 'wb') as fobj:
            fobj.write(priv)


if __name__ == '__main__':
    main()
