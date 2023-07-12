# coding=utf-8
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2023  Piotr Bartman <prbartman@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
# USA.
"""Direct communication with ctap device."""

import asyncio
import logging
import logging.handlers
import sys

from fido2.client import _ctap2client_err
from fido2.ctap import CtapError
from fido2.ctap1 import APDU, ApduError
from fido2.hid import CtapHidDevice

from qubesctap import const
from qubesctap.protocol import RequestWrapper, ApduResponseWrapper


async def mux(
        untrusted_request, stream=None, devices=None, timeout=const.TIMEOUT,
        *, loop=None):
    """Send request (APDU/CBOR) to all discovered devices
    and return one response.

    If a valid response came, return it.
    Else, if at least one
    :py:obj:`APDU.USE_NOT_SATISFIED` came, return that.
    Else, return some other response.

    If no devices, return :py:obj:`None`.
    """

    if stream is None:
        stream = sys.stdout.buffer
    if devices is None:
        devices = list(CtapHidDevice.list_devices())
    if loop is None:
        loop = asyncio.get_event_loop()

    response = await _mux(
        untrusted_request=untrusted_request,
        devices=devices,
        timeout=timeout,
        loop=loop
    )

    stream.write(bytes(response))
    stream.close()

    return response


async def _mux(*, untrusted_request, devices, timeout, loop):
    log = logging.getLogger('mux')

    pending = {loop.run_in_executor(None, call_device, device, untrusted_request)
        for device in devices}
    log.debug('pending=%r', pending)

    if not pending:
        # no device plugged -- send a response as if the device wasn't touched,
        # but log a fat message, so there is a chance to debug it...
        log.warning('no device, sending fake USE_NOT_SATISFIED')
        return ApduResponseWrapper(ApduError(APDU.USE_NOT_SATISFIED))

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

            if result.is_ok:
                while pending:
                    pending.pop().cancel()
                return result

            if response is None \
                    or isinstance(result.data, ApduError) \
                    and result.data.code == APDU.USE_NOT_SATISFIED:
                response = result

    return response


def call_device(device, untrusted_request):
    """Send bytes to device and get wrapped response.

    The request is validated before being sent to the device.
    """
    log = logging.getLogger('mux.device')

    try:
        request = RequestWrapper.from_bytes(untrusted_request)
        log.debug("request: %s", bytes(request))

        try:
            response = request.execute(device)
        except CtapError as err:
            # pylint: disable=raise-missing-from
            raise _ctap2client_err(err)
    finally:
        device.close()

    log.debug('response %s', bytes(response))

    return response
