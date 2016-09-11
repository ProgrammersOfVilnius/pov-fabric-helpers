#!/usr/bin/env python
import os
from setuptools import setup

here = os.path.dirname(__file__)
with open(os.path.join(here, 'README.rst')) as f:
    long_description = f.read()
with open(os.path.join(here, 'CHANGES.rst')) as f:
    long_description += '\n\n' + f.read()

setup(
    name='pov-fabric-helpers',
    version='0.3',
    author='Marius Gedminas',
    author_email='marius@pov.lt',
    url='https://github.com/ProgrammersOfVilnius/pov-fabric-helpers/',
    description='Fabric helpers we use at PoV',
    long_description=long_description,
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
    ],
    license='MIT',

    py_modules=['pov_fabric'],
    zip_safe=False,
    install_requires=['Fabric'],
)
