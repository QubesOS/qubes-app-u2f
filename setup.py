#!/usr/bin/python3 -O

import os
import pathlib
import setuptools
import setuptools.command.install

from qubesu2f import __version__
assert __version__ == pathlib.Path('version').read_text().strip()

def get_console_scripts(path):
    path = pathlib.Path(path)
    pkg = '.'.join(path.parts)

    for p in path.glob('*.py'):
        if not p.is_file() or p.stem == '__init__':
            continue
        yield p.stem.replace('_', '-'), '{}.{}'.format(pkg, p.stem)

# create simple scripts that run much faster than "console entry points"
class CustomInstall(setuptools.command.install.install):
    def run(self):
        bin = os.path.join(self.root, "usr/bin")
        os.makedirs(bin, exist_ok=True)
        for file, pkg in get_console_scripts('qubesu2f/tools'):
           path = os.path.join(bin, file)
           with open(path, "w") as f:
               f.write(
"""#!/usr/bin/python3
from {} import main
import sys
if __name__ == '__main__':
        sys.exit(main())
""".format(pkg))

           os.chmod(path, 0o755)
        setuptools.command.install.install.run(self)

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
            'python_fido2',
        ],
        packages=setuptools.find_packages(),
        package_data={
            'qubesu2f.tests': ['*.xpi'],
        },
        cmdclass={
            'install': CustomInstall,
        },
    )
