# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name="python-signify",
    version='0.0.0-DEVEL',
    url='https://github.com/bjornedstrom/python-signify',
    license='MIT',
    description="OpenBSD Signify for Python",
    author=u'Björn Edström',
    author_email='be@bjrn.se',
    packages=['signify'],
    classifiers=[
        'Operating System :: Unix',
        'Topic :: Security :: Cryptography',
    ],
)
