#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2017  Wojtek Porczyk <woju@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

"""Qrexec call: u2f.Authenticate"""

import argparse
import asyncio
import os
import sys

from qubesctap.protocol import RequestWrapper
from qubesctap import sys_usb
from qubesctap.sys_usb.mux import mux as default_mux

parser = argparse.ArgumentParser()
parser.add_argument('credential_id_hash', metavar='QREXEC_SERVICE_ARGUMENT',
                    default=os.getenv('QREXEC_SERVICE_ARGUMENT'),
                    nargs='?')


async def main_async(args=None, mux=default_mux):
    """Main async routine of ``u2f.Register`` qrexec call"""

    args = parser.parse_args(args)
    sys_usb.setup_logging()

    untrusted_request = sys.stdin.buffer.read()

    request = RequestWrapper.from_bytes(untrusted_request)

    allow_list = list(request.qrexec_args)
    if args.credential_id_hash is not None:
        if args.credential_id_hash not in allow_list:
            return 1
        request.trim_allow_list(args.credential_id_hash)

    await mux(untrusted_request)
    return 0

def main(args=None, mux=default_mux):
    """Main routine of ``u2f.Register`` qrexec call"""
    return asyncio.run(main_async(args, mux))

if __name__ == '__main__':
    sys.exit(main())
