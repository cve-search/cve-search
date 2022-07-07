#!/usr/bin/env python
from setuptools import setup
from feedformatter import __version__ as version

setup(
    name='feedformatter',
    version=version,
    description='A Python library for generating news feeds in RSS and Atom formats',
    author='Luke Maurits',
    author_email='luke@maurits.id.au',
    url='http://code.google.com/p/feedparser/',
    license='http://www.luke.maurits.id.au/software/bsdlicense.txt',
    py_modules=['feedformatter'],
)
