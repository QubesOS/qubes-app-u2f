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

"""Qrexec call: ctap.MakeCredential"""

import asyncio
import logging
import os
import sys

from qubesctap.protocol import InvalidCommandError
from qubesctap import sys_usb, const
from qubesctap.sys_usb.mux import mux as default_mux


def main(mux=default_mux):
    """Main routine of ``ctap.MakeCredential`` qrexec call"""

    sys_usb.setup_logging()
    loop = asyncio.get_event_loop()

    response = loop.run_until_complete(mux(sys.stdin.buffer.read()))

    try:
        loop.run_until_complete(qrexec_register_argument(
            'ctap.GetAssertion', response.qrexec_arg))
    except InvalidCommandError:
        pass


async def qrexec_register_argument(rpcname, argument, frontend=None):
    """
    Register qrexec policy argument.
    """
    if frontend is None:
        frontend = os.environ['QREXEC_REMOTE_DOMAIN']

    logging.info(
        'attempting to register qrexec rpcname %s argument %s frontend %s',
        rpcname, argument, frontend)

    qrexec_client = await asyncio.create_subprocess_exec(
        const.QREXEC_CLIENT, frontend,
        f'policy.RegisterArgument+{rpcname}',
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await qrexec_client.communicate(argument.encode('ascii'))

    if qrexec_client.returncode:
        logging.warning(
            'policy argument registration failed for'
            ' rpcname %s argument %s frontend %s; ignoring',
            rpcname, argument, frontend)
        logging.debug('stdout %r stderr %r', stdout, stderr)


if __name__ == '__main__':
    sys.exit(main())
