#!/usr/bin/python3 -O

import os
import pathlib
import setuptools

from qubesu2f import __version__
assert __version__ == pathlib.Path('version').read_text().strip()

def get_console_scripts(path):
    path = pathlib.Path(path)
    pkg = '.'.join(path.parts)

    for p in path.glob('*.py'):
        if not p.is_file() or p.stem == '__init__':
            continue
        yield '{} = {}.{}:main'.format(p.stem.replace('_', '-'), pkg, p.stem)

if __name__ == '__main__':
    setuptools.setup(
        name='qubesu2f',
        version=__version__,
        author='Wojtek Porczyk',
        author_email='woju@invisiblethingslab.com',
        maintainer='Invisible Things Lab',
        description='Qubes U2F proxy',
        license='GPL2+',
        url='https://github.com/QubesOS/qubes-app-u2f',
        requires=[
            'python_u2flib_host',
        ],
        packages=setuptools.find_packages(),
        entry_points={
            'console_scripts': list(get_console_scripts('./qubesu2f/tools')),
        },
    )
