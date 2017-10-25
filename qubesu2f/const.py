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

'''Constants for U2F protocol.
'''
# pylint: disable=invalid-name,missing-docstring

import enum

TIMEOUT = 5

class _UnknownDict(dict):
    def __missing__(self, key):
        return 'Unknown {:#x}.'.format(key)

HID_FRAME_SIZE = 64

# This is 7609. See [U2FRawMsgs 2.4] for where it came from.
MAX_APDU_SIZE = HID_FRAME_SIZE - 7 + 0x80 * (HID_FRAME_SIZE - 5)

#
# U2F Raw Messages
#

@enum.unique
class U2F(enum.IntEnum):
    REGISTER = 0x01
    AUTHENTICATE = 0x02  # P1 = 0x03/0x07/0x08
    VERSION = 0x03

@enum.unique
class U2F_SW(enum.IntEnum):  # "status word", c.f. ISO7816-4 5.1.2
    NO_ERROR = 0x9000
    CONDITIONS_NOT_SATISFIED = 0x6985
    WRONG_DATA = 0x6A80
    WRONG_LENGTH = 0x6700
    CLA_NOT_SUPPORTED = 0x6E00
    INS_NOT_SUPPORTED = 0x6D00

    # This one is taken directly from ISO7816-4, not from U2FRawMsgs,
    # we use it when qrexec call fails
    EXECUTION_ERROR = 0x6400
    NO_DIAGNOSIS = 0x6F00

    @classmethod
    def from_buffer(cls, buffer, offset=0):
        from . import util
        return cls(util.u16n_read(buffer, offset=offset))
    def __bytes__(self):
        from . import util
        return util.u16n_write(self)
    def __eq__(self, other):
        if isinstance(other, bytes):
            return other == bytes(self)
        return NotImplemented

    # this is needed for hashability in the face of __eq__ and class lookup in
    # ResponseAPDU.__new__()/ResponseAPDUMeta.get_class_for_sw()
    def __hash__(self):
        return hash(bytes(self))

U2F_SW_MSG = _UnknownDict({
    U2F_SW.NO_ERROR:
        'The command completed successfully without error.',
    U2F_SW.CONDITIONS_NOT_SATISFIED:
        'The request was rejected due to test-of-user-presence being required.',
    U2F_SW.WRONG_DATA:
        'The request was rejected due to an invalid key handle.',
    U2F_SW.WRONG_LENGTH:
        'The length of the request was invalid.',
    U2F_SW.CLA_NOT_SUPPORTED:
        'The Class byte of the request is not supported.',
    U2F_SW.INS_NOT_SUPPORTED:
        'The Instruction of the request is not supported.',

    U2F_SW.EXECUTION_ERROR:
        'Qrexec call failed.',
    U2F_SW.NO_DIAGNOSIS:
        'No precise diagnosis (ISO7816-4).',
})

# Register

U2F_NONCE_SIZE = 32  # "challenge parameter"
U2F_APPID_SIZE = 32  # "application parameter"

U2F_REGISTER_ID = 0x05  # magic value of the first byte of Register response

P256_POINT_SIZE = 65
MAX_KH_SIZE = 128

# Authenticate

@enum.unique
class U2F_AUTH(enum.IntEnum):
    CHECK_ONLY = 0x07
    ENFORCE = 0x03
    NO_ENFORCE = 0x08

@enum.unique
class U2F_AUTH_USER_PRESENCE(enum.IntEnum):
    NOT_VERIFIED = 0
    VERIFIED = 1

# Version

U2F_VERSION = 'U2F_V2'

#
# HID encapsulation
#

U2FHID_IF_VERSION = 2

@enum.unique
class U2FHID_CID(enum.IntEnum):
    BROADCAST = 0xffffffff
    RESERVED = 0x0

@enum.unique
class U2FHID_TYPE(enum.IntEnum):
    INIT = 1
    CONT = 0

INIT_NONCE_SIZE = 8

@enum.unique
class U2FHID(enum.IntEnum):
    PING  = 0x01
    MSG   = 0x03
    LOCK  = 0x04
    INIT  = 0x06
    WINK  = 0x08
    SYNC  = 0x3c
    ERROR = 0x3f

@enum.unique
class U2FHID_CAPABILITY(enum.IntEnum):
    WINK = 1 << 0
    LOCK = 1 << 1

@enum.unique
class U2FHID_ERR(enum.IntEnum):
    NONE = 0
    INVALID_CMD = 1
    INVALID_PAR = 2
    INVALID_LEN = 3
    INVALID_SEQ = 4
    MSG_TIMEOUT = 5
    CHANNEL_BUSY = 6

    # these are out of spec, but found in CTAP2 and in reference implementation
    LOCK_REQUIRED = 0x0A
    INVALID_CHANNEL = 0x0B
    OTHER = 0x7F

U2FHID_ERR_MSG = _UnknownDict({
    U2FHID_ERR.NONE:
        'Succeess',
    U2FHID_ERR.INVALID_CMD:
        'The command in the request is invalid',
    U2FHID_ERR.INVALID_PAR:
        'The parameter(s) in the request is invalid',
    U2FHID_ERR.INVALID_LEN:
        'The length field (BCNT) is invalid for the request',
    U2FHID_ERR.INVALID_SEQ:
        'The sequence does not match expected value',
    U2FHID_ERR.MSG_TIMEOUT:
        'The message has timed out',
    U2FHID_ERR.CHANNEL_BUSY:
        'The device is busy for the requesting channel',

    # these are out of spec, but found in reference implementation
    U2FHID_ERR.LOCK_REQUIRED:
        'Command requires channel lock (CTAP2)',
    U2FHID_ERR.INVALID_CHANNEL:
        'Command not allowed on this cid (CTAP2)',
    U2FHID_ERR.OTHER:
        'Other unspecified error (CTAP2)',
})

QREXEC_CLIENT = '/usr/bin/qrexec-client-vm'

#
# usbmon
#

# /usr/include/asm-generic/ioctl.h
#_IOC_NONE = 0
_IOC_WRITE = 1
#_IOC_READ = 2

def _IOC(dir, type, nr, size):
    # pylint: disable=redefined-builtin
    return (dir << 30) | (type << 8) | (nr << 0) | (size << 16)

def _IOW(type, nr, size):
    # pylint: disable=redefined-builtin
    return _IOC(_IOC_WRITE, type, nr, size)

MON_IOC_MAGIC = 0x92
#MON_IOCX_GETX = _IOW(MON_IOC_MAGIC, 10, ctypes.sizeof(_USBMonGetArg))
