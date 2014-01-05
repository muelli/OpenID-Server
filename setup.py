#!/usr/bin/env python

import sys
import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


setup(
    name='ownopenidserver',
    version='0.1',
    description='ownopenidserver is a small and very own OpenID server for your site.',
    url='https://github.com/schoeke/OpenID-Server',
    packages=['ownopenidserver',
              ],
    license='GPLv3+',
    author='',
    author_email='',
    classifiers=[
        #"Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        #"License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content :: CGI Tools/Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    #scripts=[],
    package_data = {
        'ownopenidserver': ['templates/*.html'],
    },
    install_requires=[
        'jinja2',
        'web.py',
        'flup',
        'html5lib',
        'python-openid',
    ],
)
