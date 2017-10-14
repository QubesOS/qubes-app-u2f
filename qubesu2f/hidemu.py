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

'''Generic U2FHID emulated device.'''

import binascii
import ctypes
import functools
import io
import itertools
import os

from . import const
from . import proto
from . import uhid
from . import util

VENDOR_ID = 0xf055
PRODUCT_ID = 0xf1d0
from . import __version__ as VERSION  # pylint: disable=wrong-import-position

class U2FHIDErrorMeta(type):
    '''Metaclass for :py:class:`U2FHIDError`'''
    # pylint: disable=no-self-argument
    def __init__(cls, name, bases, dct):
        super().__init__(name, bases, dct)

        # pylint: disable=access-member-before-definition
        if not cls.__doc__:
            try:
                cls.__doc__ = const.U2FHID_ERR_MSG[dct['ERR']]
            except KeyError:
                pass

# pylint: disable=missing-docstring

class U2FHIDError(Exception):
    ERR = const.U2FHID_ERR.NONE

class U2FHIDInvalidCmdError(U2FHIDError):
    ERR = const.U2FHID_ERR.INVALID_CMD

class U2FHIDInvalidParError(U2FHIDError):
    ERR = const.U2FHID_ERR.INVALID_PAR

class U2FHIDInvalidLenError(U2FHIDError):
    ERR = const.U2FHID_ERR.INVALID_LEN

class U2FHIDInvalidSeqError(U2FHIDError):
    ERR = const.U2FHID_ERR.INVALID_SEQ

class U2FHIDMsgTimeoutError(U2FHIDError):
    ERR = const.U2FHID_ERR.MSG_TIMEOUT

class U2FHIDChannelBusyError(U2FHIDError):
    ERR = const.U2FHID_ERR.CHANNEL_BUSY

# these are out of spec, but found in reference implementation
class U2FHIDLockRequiredError(U2FHIDError):
    ERR = const.U2FHID_ERR.LOCK_REQUIRED

class U2FHIDInvalidCidError(U2FHIDError):
    ERR = const.U2FHID_ERR.INVALID_CID

class U2FHIDOtherError(U2FHIDError):
    ERR = const.U2FHID_ERR.OTHER

# pylint: enable=missing-docstring

def u2fhid_handler(*, expected_cid=None, expected_bcnt=None):
    '''Mark properties of ``handle_u2fhid_*`` methods.'''
    def decorator(obj):
        # pylint: disable=missing-docstring
        if expected_cid is not None:
            obj.u2fhid_expected_cid = expected_cid
        if expected_bcnt is not None:
            obj.u2fhid_expected_bcnt = expected_bcnt
        return obj
    return decorator


class U2FHIDChannel:
    '''Represents one channel in U2FHID device.

    This class is responsible for reassembly of fragmented packets.
    '''
    def __init__(self, cid):
        self.cid = cid

        self.callback = None
        self.data = None
        self.remaining = None
        self.expected_seq = None

    def init(self, init, callback):
        '''Handle TYPE_INIT U2FHID packet'''
        if self.remaining is not None:
            raise U2FHIDChannelBusyError()

        self.callback = callback
        self.data = io.BytesIO()
        self.remaining = init.bcnt
        self.get_data_from_array(init.data)
        self.expected_seq = 0

    def cont(self, cont):
        '''Handle TYPE_CONT U2FHID packet.

        :raises U2FHIDInvalidSeqError:
        '''
        if cont.seq != self.expected_seq:
            raise U2FHIDInvalidSeqError()
        self.get_data_from_array(cont.data)
        self.expected_seq += 1

    def get_data_from_array(self, array):
        '''Get data from :py:class:`ctypes.Array`

        :raises U2FHIDInvalidSeqError:
        '''
        if self.is_finished():
            raise U2FHIDInvalidSeqError()
        self.remaining -= self.data.write(
            ctypes.string_at(array, min(ctypes.sizeof(array), self.remaining)))
        assert self.remaining >= 0, self.remaining

    def is_finished(self):
        ''':obj:`True` if last packet was received, :obj:`False` otherwise.'''
        return self.remaining == 0

    # 2.5.3 _SYNC
    def sync(self):
        '''Handle U2FHID_SYNC packet. Resets the channel to a known state.'''
        self.callback = None
        self.data = None
        self.remaining = None
        self.expected_seq = None

    async def execute(self):
        '''Invoke the callback.'''
        await self.callback(self.cid, self.data.getvalue())
        self.sync()


class U2FHIDDevice(uhid.UHIDDevice):
    '''Abstract U2FHID emulated device.

    Subclass should overload :meth:`handle_u2f_register`,
    :meth:`handle_u2f_authenticate` and :meth:`handle_u2f_version` methods, and
    optionally :attr:`name`, :attr:`vendor`, :attr:`product` and
    :attr:`version` attributes (see parent class).

    The following example on just spews some errors on U2F_REGISTER and
    U2F_AUTHENTICATE, but you should return valid response APDUs like in
    ``handle_u2f_version``:

    >>> class MyU2FHIDDevice(U2FHIDDevice):
    ...     async def handle_u2f_register(self, apdu):
    ...         return bytes(const.U2F_SW.CONDITIONS_NOT_SATISFIED)
    ...     async def handle_u2f_authenticate(self, apdu):
    ...         return bytes(const.U2F_SW.CLA_NOT_SUPPORTED)
    ...     async def handle_u2f_version(self, apdu):
    ...         return (const.U2F_VERSION.encode('ascii')
    ...                 + bytes(const.U2F_SW.NO_ERROR))
    '''

    name = 'Qubes OS U2F device'
    vendor = VENDOR_ID
    product = PRODUCT_ID
    version = VERSION

    # stolen from Yubikey 4 (1050:0407)
    rdesc = binascii.unhexlify(''.join('''
        06 D0 F1 09 01 A1 01 09 20 15 00 26 FF 00 75 08
        95 40 81 02 09 21 15 00 26 FF 00 75 08 95 40 91
        02 C0'''.split()))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.channels = {
            const.U2FHID_CID.BROADCAST:
                U2FHIDChannel(const.U2FHID_CID.BROADCAST)}

    async def handle_hid_output(self, event):
        # pylint: disable=too-many-branches

        # TODO timeout?

        # XXX This is a workaround agains uhid, which sometimes includes one
        # byte in front of actual data. What it depends on?
        packet = proto.U2FHIDPacket.from_address(
            ctypes.addressof(event.output.data) + event.output.size
            - const.HID_FRAME_SIZE)
        self.log.getChild('u2fhid').debug('handle_hid_output() %r', packet)
        try:
            if packet.is_init():
                if packet.init.cmd == const.U2FHID.SYNC:
                    # handle this one directly
                    try:
                        self.channels[packet.cid].sync()
                    except KeyError:
                        raise U2FHIDInvalidCidError()
                    return

                try:
                    cmd = const.U2FHID(packet.init.cmd)
                    method = getattr(self, 'handle_u2fhid_' + cmd.name.lower())
                except (ValueError, AttributeError):
                    raise U2FHIDInvalidCmdError()

                try:
                    expected_bcnt = method.u2fhid_expected_bcnt
                    if packet.init.bcnt != expected_bcnt:
                        raise U2FHIDInvalidLenError()
                except AttributeError:
                    pass

                try:
                    expected_cid = method.u2fhid_expected_cid
                    if packet.cid != expected_cid:
                        raise U2FHIDInvalidCmdError()
                except AttributeError:
                    pass

                try:
                    channel = self.channels[packet.cid]
                except KeyError:
                    raise U2FHIDInvalidCidError()

                channel.init(packet.init, method)

            else:
                try:
                    channel = self.channels[packet.cid]
                except KeyError:
                    raise U2FHIDInvalidCidError()
                channel.cont(packet.cont)

            if channel.is_finished():
                await self.channels[packet.cid].execute()

        except U2FHIDError as err:
            await self.write_u2fhid_error(packet.cid, err)

    async def write_u2fhid_response(self, cid, cmd, data):
        '''Send a U2FHID response packets, fragmenting data if needed.

        :param int cid: channel id
        :param const.U2FHID cmd: command
        :param bytes data: payload
        '''
        assert len(data) <= const.MAX_APDU_SIZE

        packet = proto.U2FHIDPacket(cid=cid)
        self.log.getChild('u2fhid').debug(
            'write_u2fhid_response(cid=%#08x, cmd=%s, data=%s)',
            cid, cmd, util.hexlify(data))
        packet.init.type = const.U2FHID_TYPE.INIT
        packet.init.cmd = cmd
        packet.init.bcnt = len(data)

        chunk_size = ctypes.sizeof(packet.init.data)
        ctypes.memmove(packet.init.data, data, min(len(data), chunk_size))
        data = data[chunk_size:]

        self.log.getChild('u2fhid').debug(
            'write_u2fhid_response(cid=%#08x, cmd=%s,) packet=%r',
            cid, cmd, packet)
        await self.write_uhid_req(uhid.UHID.INPUT2, data=bytes(packet))

        packet.cont.type = const.U2FHID_TYPE.CONT
        chunk_size = ctypes.sizeof(packet.cont.data)
        seq = itertools.count()

        while data:
            packet.cont.seq = next(seq)
            ctypes.memmove(packet.cont.data, data, min(len(data), chunk_size))
            data = data[chunk_size:]

            self.log.getChild('u2fhid').debug(
                'write_u2fhid_response(cid=%#08x, cmd=%s,) packet=%r',
                cid, cmd, packet)
            await self.write_uhid_req(uhid.UHID.INPUT2, data=bytes(packet))

    async def write_u2fhid_error(self, cid, exc):
        '''Send a U2FHID ERROR packet

        :param int cid: channel id
        :param U2FHIDError exc: the exception
        '''
        self.log.getChild('u2fhid').debug(
            'write_u2fhid_error(cid=%#08x, exc=%s)', cid, exc)
        await self.write_u2fhid_response(cid,
            const.U2FHID.ERROR, bytes((exc.ERR,)))

    def create_new_channel(self):
        '''Create a new channel.

        :returns: channel id
        :rtype: int
        '''
        cid = const.U2FHID_CID.BROADCAST
        assert cid in self.channels
        while cid in self.channels:
            cid = functools.reduce(lambda x, y: (x << 8) + y, os.urandom(4))
        self.channels[cid] = U2FHIDChannel(cid)
        self.log.getChild('u2fhid').debug(
            'create_new_channel() -> %#08x', cid)
        return cid

    # 4.1 mandatory commands

    # 4.1.1 _MSG
    async def handle_u2fhid_msg(self, cid, data):
        '''Handle U2FHID_MSG by calling ``handle_u2f_*`` method.'''
        self.log.getChild('u2fhid').debug(
            'handle_u2fhid_msg(cid=%#08x, data=...)', cid)
        try:
            apdu = proto.CommandAPDU.from_buffer(data)
            self.log.getChild('u2fhid').debug(
                'handle_u2fhid_msg(cid=%#08x) apdu=%r', cid, apdu)
            handle = getattr(self, 'handle_u2f_' + apdu.ins.name.lower())
            await self.write_u2fhid_response(cid, const.U2FHID.MSG,
                bytes(await handle(apdu)))
        except proto.APDUError as err:
            self.log.getChild('u2fhid').info(
                'handle_u2fhid_msg(cid=%#08x) err=%r', cid, err, exc_info=err)
            await self.write_u2fhid_response(cid, const.U2FHID.MSG, bytes(err))

    # 4.1.2 _INIT
    @u2fhid_handler(expected_bcnt=8, expected_cid=const.U2FHID_CID.BROADCAST)
    async def handle_u2fhid_init(self, cid, data):
        '''Handle U2FHID_INIT.

        Creates a new channel.
        '''
        self.log.getChild('u2fhid').debug('handle_u2fhid_init()')
        resp = proto.U2FHIDInitResp()
        resp.nonce = data
        resp.cid = self.create_new_channel()
        resp.version = const.U2FHID_IF_VERSION

        resp.major = (self.version >> 24) & 0xff
        resp.minor = (self.version >> 16) & 0xff
        resp.build = (self.version >>  8) & 0xff

        resp.caps = sum(cap for cap in const.U2FHID_CAPABILITY
            if hasattr(self, 'handle_u2fhid_' + cap.name.lower()))

        await self.write_u2fhid_response(cid, const.U2FHID.INIT, bytes(resp))

    # 4.1.3 _PING
    @u2fhid_handler()
    async def handle_u2fhid_ping(self, cid, data):
        '''Handle U2FHID_PING.
        '''
        self.log.getChild('u2fhid').debug('handle_u2fhid_ping()')
        await self.write_u2fhid_response(cid, const.U2FHID.PING, data)

    # 4.1.4 _ERROR only in response

    # 4.2 optional commands

#   # 4.2.1 _WINK
#   @u2fhid_handler(expected_bcnt=0)
#   async def handle_u2fhid_wink(self, cid, data):
#       raise NotImplementedError()

#   # 4.1.2 _LOCK
#   @u2fhid_handler(expected_bcnt=1)
#   async def handle_u2fhid_lock(self, cid, data):
#       raise NotImplementedError()


    async def handle_u2f_register(self, apdu):
        '''Handle U2F_REGISTER message.

        Subclass should overload this method with appropriate implementation.
        '''
        raise NotImplementedError()

    async def handle_u2f_authenticate(self, apdu):
        '''Handle U2F_AUTHENTICATE message.

        Subclass should overload this method with appropriate implementation.
        '''
        raise NotImplementedError()

    async def handle_u2f_version(self, apdu):
        '''Handle U2F_VERSION message.

        Subclass should overload this method with appropriate implementation.
        '''
        raise NotImplementedError()
