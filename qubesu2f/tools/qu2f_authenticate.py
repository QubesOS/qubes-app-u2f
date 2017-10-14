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

'''Qrexec call: u2f.Register'''

import argparse
import asyncio
import hashlib
import logging  # pylint: disable=unused-import
import logging.handlers  # pylint: disable=unused-import
import os
import sys

from .. import proto
from .. import tools

parser = argparse.ArgumentParser()
parser.add_argument('key_handle_hash', metavar='QREXEC_SERVICE_ARGUMENT',
    default=os.getenv('QREXEC_SERVICE_ARGUMENT'),
    nargs='?')

def main(args=None):
    '''Main routine of ``u2f.Register`` qrexec call'''

    # uncomment for debugging
#   logging.basicConfig(level=logging.NOTSET,
#       format='%(name)s %(message)s',
#       handlers=[logging.handlers.SysLogHandler(address='/dev/log',
#           facility=logging.handlers.SysLogHandler.LOG_LOCAL2)])

    args = parser.parse_args()

    with proto.apdu_error_responder():
        apdu = proto.CommandAPDUAuthenticate.from_stream(
            sys.stdin.buffer)

    if (args.key_handle_hash is not None and args.key_handle_hash !=
            hashlib.sha256(apdu.key_handle).hexdigest()[:32]):
        return 1

    asyncio.get_event_loop().run_until_complete(tools.mux(apdu))

if __name__ == '__main__':
    sys.exit(main())
