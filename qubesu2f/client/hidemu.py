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

"""Generic CTAPHID emulated device."""

import asyncio
import binascii
import ctypes
import enum
import functools
import io
import itertools
import os
from typing import Optional, BinaryIO, Dict

from fido2.ctap import CtapError
from fido2.ctap1 import APDU, ApduError  # pylint: disable=unused-import
from fido2.hid import CTAPHID, CAPABILITY

import qubesu2f.client.hid_data
from qubesu2f import const
from qubesu2f import util
from qubesu2f.client import uhid
from qubesu2f.protocol import RequestWrapper
from qubesu2f.util import int_to_bytes

VENDOR_ID = 0xf055
PRODUCT_ID = 0xf1d0
from qubesu2f import __version__ as VERSION  # pylint: disable=wrong-import-position

# pylint: disable=invalid-name,missing-class-docstring
@enum.unique
class CTAPHID_CID(enum.IntEnum):
    BROADCAST = 0xffffffff
    RESERVED = 0x0

def ctaphid_handler(*, expected_cid=None, expected_bcnt=None):
    """Mark properties of ``handle_ctaphid_*`` methods."""
    def decorator(obj):
        # pylint: disable=missing-docstring
        if expected_cid is not None:
            obj.ctaphid_expected_cid = expected_cid
        if expected_bcnt is not None:
            obj.ctaphid_expected_bcnt = expected_bcnt
        return obj
    return decorator


class CTAPHIDChannel:
    """Represents one channel in CTAPHID device.

    This class is responsible for reassembly of fragmented packets.
    """
    def __init__(self, cid):
        self.cid = cid

        self.callback= None
        self.data: Optional[BinaryIO] = None
        self.remaining: Optional[int] = None
        self.expected_seq = None

    def init(self, init, callback):
        """Handle TYPE_INIT CTAPHID packet"""
        if self.remaining is not None:
            raise CtapError(CtapError.ERR.CHANNEL_BUSY)

        self.callback = callback
        self.data = io.BytesIO()
        self.remaining = init.bcnt
        self.get_data_from_array(init.data)
        self.expected_seq = 0

    def cont(self, cont):
        """Handle TYPE_CONT CTAPHID packet.

        :raises CTAPHIDInvalidSeqError:
        """
        if cont.seq != self.expected_seq:
            raise CtapError(CtapError.ERR.INVALID_SEQ)
        self.get_data_from_array(cont.data)
        self.expected_seq += 1

    def get_data_from_array(self, array):
        """Get data from :py:class:`ctypes.Array`

        :raises CTAPHIDInvalidSeqError:
        """
        if self.is_finished() or self.data is None or self.remaining is None:
            raise CtapError(CtapError.ERR.INVALID_SEQ)
        self.remaining -= self.data.write(
            ctypes.string_at(array, min(ctypes.sizeof(array), self.remaining)))
        assert self.remaining >= 0, self.remaining

    def is_finished(self):
        """:obj:`True` if last packet was received, :obj:`False` otherwise."""
        return self.remaining == 0

    # SYNC
    def sync(self):
        """Handle CTAPHID_SYNC packet. Resets the channel to a known state."""
        self.callback = None
        self.data = None
        self.remaining = None
        self.expected_seq = None

    def execute(self):
        """Invoke the callback."""
        assert self.callback is not None # CTAPHIDChannel is not initialized
        assert self.is_finished()
        assert self.data is not None
        data = self.data.getvalue()  # type: ignore
        callback = self.callback
        self.sync()
        return callback(self.cid, data)


class CTAPHIDDevice(uhid.UHIDDevice):
    """Abstract CTAPHID emulated device.

    Subclass should overload :meth:`handle_u2f_register`,
    :meth:`handle_u2f_authenticate` and :meth:`handle_u2f_version` methods, and
    optionally :attr:`name`, :attr:`vendor`, :attr:`product` and
    :attr:`version` attributes (see parent class).

    The following example on just spews some errors on U2F_REGISTER and
    U2F_AUTHENTICATE, but you should return valid response APDUs like in
    ``handle_u2f_version``:

    >>> class MyCTAPHIDDevice(CTAPHIDDevice):
    ...     async def handle_u2f_register(self, apdu):
    ...         return bytes(APDU.USE_NOT_SATISFIED)
    ...     async def handle_u2f_authenticate(self, apdu):
    ...         return bytes(APDU.WRONG_DATA)
    ...     async def handle_u2f_version(self, apdu):
    ...         return (const.U2F_VERSION.encode('ascii')
    ...                 + bytes(APDU.OK))
    """

    name = 'Qubes OS CTAP device'
    vendor = VENDOR_ID
    product = PRODUCT_ID
    version = VERSION  # type: ignore #see: uhid.UHIDDevice._normalize_version()

    # stolen from Yubikey 4 (1050:0407)
    rdesc = binascii.unhexlify(''.join('''
        06 D0 F1 09 01 A1 01 09 20 15 00 26 FF 00 75 08
        95 40 81 02 09 21 15 00 26 FF 00 75 08 95 40 91
        02 C0'''.split()))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.channels: Dict[int, CTAPHIDChannel] = {
            CTAPHID_CID.BROADCAST:
                CTAPHIDChannel(CTAPHID_CID.BROADCAST)}

    def handle_hid_output(self, event):
        # pylint: disable=too-many-branches

        # This is a workaround against uhid, which sometimes includes one
        # byte in front of actual data. What it depends on?
        packet = qubesu2f.client.hid_data.CTAPHIDPacket.from_address(
            ctypes.addressof(event.output.data) + event.output.size
            - const.HID_FRAME_SIZE)
        self.log.getChild('ctaphid').debug('handle_hid_output() %r', packet)
        try:
            if packet.is_init():
                try:
                    cmd = CTAPHID(packet.init.cmd)
                    method = getattr(self, 'handle_ctaphid_' + cmd.name.lower())
                except (ValueError, AttributeError):
                    # pylint: disable=raise-missing-from
                    raise CtapError(CtapError.ERR.INVALID_COMMAND)

                try:
                    expected_bcnt = method.ctaphid_expected_bcnt
                    if packet.init.bcnt != expected_bcnt:
                        raise CtapError(CtapError.ERR.INVALID_LENGTH)
                except AttributeError:
                    pass

                try:
                    expected_cid = method.ctaphid_expected_cid
                    if packet.cid != expected_cid:
                        raise CtapError(CtapError.ERR.INVALID_CHANNEL)
                except AttributeError:
                    pass

                try:
                    channel = self.channels[packet.cid]
                except KeyError:
                    # pylint: disable=raise-missing-from
                    raise CtapError(CtapError.ERR.INVALID_CHANNEL)

                channel.init(packet.init, method)

            else:
                try:
                    channel = self.channels[packet.cid]
                except KeyError:
                    # pylint: disable=raise-missing-from
                    raise CtapError(CtapError.ERR.INVALID_CHANNEL)
                channel.cont(packet.cont)

            if channel.is_finished():
                asyncio.ensure_future(self.channels[packet.cid].execute(),
                    loop=self.loop)

        except CtapError as err:
            asyncio.ensure_future(self.write_ctap_error(packet.cid, err),
                loop=self.loop)

    async def write_ctaphid_response(self, cid, cmd, data):
        """Send a CTAPHID response packets, fragmenting data if needed.

        :param int cid: channel id
        :param CTAPHID cmd: command
        :param bytes data: payload
        """
        assert len(data) <= const.MAX_MSG_SIZE

        packet = qubesu2f.client.hid_data.CTAPHIDPacket(cid=cid)
        self.log.getChild('ctaphid').debug(
            'write_ctaphid_response(cid=%#08x, cmd=%s, data=%s)',
            cid, cmd, util.hexlify(data))
        packet.init.type = const.CTAPHID_TYPE.INIT
        packet.init.cmd = cmd
        packet.init.bcnt = len(data)

        chunk_size = ctypes.sizeof(packet.init.data)
        ctypes.memmove(packet.init.data, data, min(len(data), chunk_size))
        data = data[chunk_size:]

        self.log.getChild('ctaphid').debug('write_ctaphid_response packet=%r',
            packet)
        await self.write_uhid_req(uhid.UHID.INPUT2, data=bytes(packet))

        packet.cont.type = const.CTAPHID_TYPE.CONT
        chunk_size = ctypes.sizeof(packet.cont.data)
        seq = itertools.count()

        while data:
            packet.cont.seq = next(seq)
            ctypes.memmove(packet.cont.data, data, min(len(data), chunk_size))
            data = data[chunk_size:]

            self.log.getChild('ctaphid').debug(
                'write_ctaphid_response(cid=%#08x, cmd=%s,) packet=%r',
                cid, cmd, packet)
            await self.write_uhid_req(uhid.UHID.INPUT2, data=bytes(packet))

    async def write_ctaphid_error(self, cid, exc):
        """Send a CTAPHID ERROR packet

        :param int cid: channel id
        :param CtapError exc: the exception
        """
        self.log.getChild('ctaphid').debug(
            'write_ctaphid_error(cid=%#08x, exc=%s)',
            cid, type(exc).__name__, exc_info=True)
        await self.write_ctaphid_response(cid,
            CTAPHID.ERROR, bytes((exc.ERR,)))

    async def write_ctap_error(self, cid, exc: CtapError):
        """Send a CTAPHID ERROR packet

        :param int cid: channel id
        :param CtapError exc: the exception
        """
        self.log.getChild('ctaphid').debug(
            'write_ctaphid_error(cid=%#08x, exc=%s)',
            cid, CtapError.ERR(exc.code).name, exc_info=True)
        await self.write_ctaphid_response(cid,
            CTAPHID.ERROR, bytes((exc.code,)))

    def create_new_channel(self):
        """Create a new channel.

        :returns: channel id
        :rtype: int
        """
        cid: int = CTAPHID_CID.BROADCAST
        assert cid in self.channels
        while cid in self.channels:
            cid = functools.reduce(lambda x, y: (x << 8) + y, os.urandom(4))
        self.channels[cid] = CTAPHIDChannel(cid)
        self.log.getChild('ctaphid').debug(
            'create_new_channel() -> %#08x', cid)
        return cid

    async def _handle_ctaphid_request(self, cid, untrusted_cmd, ctaphid, protocol):
        self.log.getChild('ctaphid').debug(
            'handle_ctaphid_%s(cid=%#08x, data=...)', ctaphid, cid)
        try:
            request = RequestWrapper.from_bytes(untrusted_cmd)
            request.raise_error(protocol=protocol)
            self.log.getChild('ctaphid').debug(
                'handle_ctaphid_%s(cid=%#08x) %s=%r',
                ctaphid, cid, ctaphid, request.data)
            handle = getattr(self, f'handle_{protocol}_' + request.name)
            await self.write_ctaphid_response(cid, CTAPHID.MSG,
                                              bytes(await handle(request)))
        except ApduError as err:
            self.log.getChild('ctaphid').info(
                'handle_ctaphid_%s(cid=%#08x) err=%r',
                ctaphid, cid, err, exc_info=True)
            await self.write_ctaphid_response(
                cid, CTAPHID.MSG, int_to_bytes(err.code))

    # 11.2.9.1.1 MSG
    async def handle_ctaphid_msg(self, cid, untrusted_cmd):
        """Handle CTAPHID_MSG by calling ``handle_ctap_*`` method."""
        await self._handle_ctaphid_request(
            cid, untrusted_cmd, ctaphid="msg", protocol="u2f"
        )

    # 11.2.9.1.2 CBOR
    async def handle_ctaphid_cbor(self, cid, untrusted_cmd):
        """Handle CTAPHID_CBOR by calling ``handle_fido2_*`` method."""
        await self._handle_ctaphid_request(
            cid, untrusted_cmd, ctaphid="cbor", protocol="fido2"
        )

    # 11.2.9.1.3 INIT
    @ctaphid_handler(expected_bcnt=8, expected_cid=CTAPHID_CID.BROADCAST)
    async def handle_ctaphid_init(self, cid, data):
        """Handle CTAPHID_INIT.

        Creates a new channel.
        """
        self.log.getChild('ctaphid').debug('handle_ctaphid_init()')
        resp = qubesu2f.client.hid_data.CTAPHIDInitResp()
        resp.nonce = data
        resp.cid = self.create_new_channel()
        resp.version = const.CTAPHID_IF_VERSION

        resp.major = (self.version >> 24) & 0xff  # type: ignore
        resp.minor = (self.version >> 16) & 0xff  # type: ignore
        resp.build = (self.version >>  8) & 0xff  # type: ignore

        resp.caps = sum(cap for cap in CAPABILITY  # type: ignore
            if hasattr(
            self, 'handle_ctaphid_' + cap.name.lower()  # type: ignore
        ))

        await self.write_ctaphid_response(cid, CTAPHID.INIT, bytes(resp))

    # 11.2.9.1.4 PING
    @ctaphid_handler()
    async def handle_ctaphid_ping(self, cid, data):
        """Handle CTAPHID_PING.
        """
        self.log.getChild('ctaphid').debug('handle_ctaphid_ping()')
        await self.write_ctaphid_response(cid, CTAPHID.PING, data)

    # 11.2.9.1.6 ERROR only in response

    # 11.2.9.2 optional commands

#   # 11.2.9.2.1 WINK
#   @ctaphid_handler(expected_bcnt=0)
#   async def handle_ctaphid_wink(self, cid, data):
#       raise NotImplementedError()

#   # 11.2.9.2.2 LOCK
#   @ctaphid_handler(expected_bcnt=1)
#   async def handle_ctaphid_lock(self, cid, data):
#       raise NotImplementedError()


    async def handle_u2f_register(self, apdu):
        """Handle U2F_REGISTER message.

        Subclass should overload this method with appropriate implementation.
        """
        raise NotImplementedError()

    async def handle_u2f_authenticate(self, apdu):
        """Handle U2F_AUTHENTICATE message.

        Subclass should overload this method with appropriate implementation.
        """
        raise NotImplementedError()

    async def handle_u2f_version(self, apdu):
        """Handle U2F_VERSION message.

        Subclass should overload this method with appropriate implementation.
        """
        raise NotImplementedError()
