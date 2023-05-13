# coding=utf-8
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2017  Wojtek Porczyk <woju@invisiblethingslab.com>
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
"""
CTAPHID data structures.
"""

import ctypes

from fido2.hid import CTAPHID

from qubesctap import util, const

# pylint: disable=too-few-public-methods,missing-docstring

class CTAPHIDInitResp(ctypes.BigEndianStructure):
    _pack_ = True
    _fields_ = (
        ('_nonce', ctypes.c_uint8 * 8),
        ('cid', ctypes.c_uint32),
        ('version', ctypes.c_uint8),
        ('major', ctypes.c_uint8),
        ('minor', ctypes.c_uint8),
        ('build', ctypes.c_uint8),
        ('caps', ctypes.c_uint8),
    )
    nonce = util.raw_data('_nonce')

assert ctypes.sizeof(CTAPHIDInitResp) == 17

class _CTAPHIDPacketInit(ctypes.BigEndianStructure):
    _pack_ = True
    _fields_ = (
        ('type', ctypes.c_uint8, 1),
        ('cmd', ctypes.c_uint8, 7),
        ('bcnt', ctypes.c_uint16),
        ('data', ctypes.c_uint8 * 57),
    )


class _CTAPHIDPacketCont(ctypes.BigEndianStructure):
    _fields_ = (
        ('type', ctypes.c_uint8, 1),
        ('seq', ctypes.c_uint8, 7),
        ('data', ctypes.c_uint8 * 59),
    )


class _CTAPHIDPacketPayloadUnion(ctypes.Union):
    _fields_ = (
        ('init', _CTAPHIDPacketInit),
        ('cont', _CTAPHIDPacketCont),
    )

# ctypes authors did forget about unions when implementing _OTHER_ENDIAN
_CTAPHIDPacketPayloadUnion.__ctype_be__ = (  # type:ignore
    _CTAPHIDPacketPayloadUnion
)


class CTAPHIDPacket(ctypes.BigEndianStructure):
    # NOTE TO SELF:
    # do not use raw_data, only the upper layer knows the size of the data
    _anonymous_ = ('u',)
    _fields_ = (
        ('cid', ctypes.c_uint32),
        ('u', _CTAPHIDPacketPayloadUnion),
    )

    def is_init(self):
        """:py:obj:`True` if TYPE_INIT, :py:obj:`False` otherwise."""
        # it does not matter which union member we choose
        return self.init.type == const.CTAPHID_TYPE.INIT

    def __repr__(self):
        if self.is_init():
            meta = f'cmd={CTAPHID(self.init.cmd)!s}, bcnt={self.init.bcnt}'
            data = self.init.data
        else:
            meta = f'seq={self.cont.seq}'
            data = self.cont.data

        return f'{type(self).__name__}(cid={self.cid:#08x}, ' \
               f'type={const.CTAPHID_TYPE(self.init.type)!s}, ' \
               f'{meta}, data={util.hexlify(data)})'

    def hexdump(self):
        if self.is_init():
            return f'{self.cid:08x} ' \
                   f'{(self.init.type << 7) + self.init.cmd:02x} ' \
                   f'{self.init.bcnt:04x} {util.hexlify(self.init.data)}'
        return f'{self.cid:08x}  {(self.cont.type << 7) + self.cont.seq:02x} ' \
               f'{util.hexlify(self.cont.data)}'

assert ctypes.sizeof(CTAPHIDPacket) == const.HID_FRAME_SIZE
