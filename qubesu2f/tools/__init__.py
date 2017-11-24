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

'''Common features of the command-line tools.'''

import asyncio
import enum
import itertools
import logging
import pathlib
import sys

import u2flib_host.u2f  # pylint: disable=import-error

from .. import const
from .. import util

# touch any of those to increase logging verbosity
DEBUG_ENABLE_PATHS = [
    '/etc/qubes/u2f-debug-enable',
    '/usr/local/etc/qubes/u2f-debug-enable',
]

async def mux(apdu, stream=None, devices=None, timeout=const.TIMEOUT, *,
        loop=None):
    '''Send APDU to all discovered devices and return one response.

    If a :py:obj:`qubesu2f.const.U2F_SW.NO_ERROR` response came, return it.
    Else, if at least one
    :py:obj:`qubesu2f.const.U2F_SW.CONDITION_NOT_SATISFIED` came, return that.
    Else, return some other response.

    If no devices, return :py:obj:`None`.
    '''

    if stream is None:
        stream = sys.stdout.buffer
    if devices is None:
        devices = u2flib_host.u2f.list_devices()
    if loop is None:
        loop = asyncio.get_event_loop()

    response = await _mux(
        apdu=apdu, devices=devices, timeout=timeout, loop=loop)

    # pylint: disable=no-member
    stream.write(bytes(response))
    stream.close()

async def _mux(*, apdu, devices, timeout, loop):
    log = logging.getLogger('mux')

    pending = {loop.run_in_executor(None, _mux_device, device, apdu)
        for device in devices}
    log.debug('pending=%r', pending)

    response = None
    while pending:
        done, pending = await asyncio.wait(pending, timeout=timeout,
            return_when=asyncio.FIRST_COMPLETED)
        logging.debug('pending=%r done=%r', pending, done)

        for fut in done:
            try:
                result = fut.result()
            except asyncio.CancelledError:
                continue

            if result.sw == const.U2F_SW.NO_ERROR:
                while pending:
                    pending.pop().cancel()
                    return result

            if (response is None or
                    result.sw == const.U2F_SW.CONDITIONS_NOT_SATISFIED):
                response = result
                continue

    return response

def _mux_device(device, capdu):
    log = logging.getLogger('mux.device')

    try:
        # pylint: disable=protected-access
        log.debug('opening device %r', device)
        device.open()
        rapdu = device._do_send_apdu(bytes(capdu))
    finally:
        device.close()

    log.debug('rapdu %s', util.hexlify(rapdu))

    # pylint: disable=no-member
    return capdu.APDU_RESPONSE.from_buffer(untrusted_data=rapdu)

def enum_getter(enum_type):
    '''For use as ``type=`` argument to :class:`argparse.ArgumentParser`'''

    enum_builtin_type = next(itertools.dropwhile(
        (lambda t: issubclass(t, enum.Enum)), enum_type.__mro__))

    if enum_builtin_type is object:
        # this is needed to solve ambiguity between 6 and '6'
        raise TypeError('need an uniform enum; mix a builtin type '
            'into your Enum class, or use IntEnum which does the same')

    def _getter(value):
        try:
            return enum_type(enum_builtin_type(value))
        except ValueError:
            return getattr(enum_type, value)

    return _getter

def setup_logging(debug=None):
    '''Setup logging

    The tools log to syslog (AUTH facility).
    '''
    logging.basicConfig(format='%(name)s %(message)s',
        handlers=[logging.handlers.SysLogHandler(address='/dev/log',
            facility=logging.handlers.SysLogHandler.LOG_AUTH)])

    if debug is None:
        debug = any(pathlib.Path(path).exists() for path in DEBUG_ENABLE_PATHS)
    if debug:
        logging.root.setLevel(logging.NOTSET)
