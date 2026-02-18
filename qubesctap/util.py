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

"""Miscellaneous utilities."""

import asyncio
import binascii
import ctypes
import hashlib
import itertools
import os
import socket


class raw_data:
    """Accessor for ctypes' byte arrays in structures.

    >>> import ctypes
    >>> class MyStruct(ctypes.Structure):
    ...     _fields_ = [
    ...         ('_size', ctypes.c_uint16),
    ...         ('_data', ctypes.c_uint8 * 32),
    ...         ('_data2', ctypes.c_uint8 * 32),
    ...     ]
    ...     data = raw_data('_data', '_size')
    ...     data2 = raw_data('_data2')
    >>> s = MyStruct()
    >>> s.data = b'spam'
    >>> assert isinstance(s.data, bytes)

    Does not work with constructor (eg. ``S(data=b'fail')``.
    """
    # pylint: disable=invalid-name,too-few-public-methods
    def __init__(self, data, size=None):
        # size field, if specified, must be long enough
        # to at least hold the value of sizeof(data)
        self.data = data
        self.size = size

    def __get__(self, instance, owner):
        if instance is None:
            return self
        data = getattr(instance, self.data)
        sizeof = ctypes.sizeof(data)
        size = getattr(instance, self.size) if self.size is not None else sizeof
        if size > sizeof:
            raise AttributeError('size > sizeof(data)')
        return ctypes.string_at(data, size)

    def __set__(self, instance, value):
        if instance is None:
            raise AttributeError()
        data = getattr(instance, self.data)
        sizeof = ctypes.sizeof(data)
        value_len = len(value)

        if value_len > sizeof:
            raise ValueError(
                f'value too long (should be at most {sizeof} bytes)')

        if self.size is not None:
            setattr(instance, self.size, value_len)

        ctypes.memset(data, 0, sizeof)
        ctypes.memmove(data, value, value_len)

    def __delete__(self, instance):
        data = getattr(instance, self.data)
        ctypes.memset(data, 0, ctypes.sizeof(data))
        if self.size is not None:
            setattr(instance, self.size, 0)


def u16n_read(buffer, offset=0):
    """Read 16-bit unsigned integer with network byte order

    It is not an error to pass buffer longer than 2 octets.

    :param bytes buffer: the buffer
    :param int offset: the offset into the buffer
    """
    return (buffer[offset] << 8) + (buffer[offset + 1])

def u16n_write(value):
    """Return network byte order representation of 16-bit unsigned integer

    If the value is greater than 0xFFFF (65535) it silently overflows. This is
    on purpose, for use in Le.
    """
    return bytes(((value >> 8) & 0xff, value & 0xff))

def hexlify(untrusted_data):
    """A slightly better version of :py:func:`binascii.hexlify()`"""
    return binascii.hexlify(untrusted_data).decode('ascii')

def maybe_hexlify(untrusted_data, maxsize=None):
    """Hexlify if argument is of type :class:`bytes` or :class:`ctypes.Array`"""
    if isinstance(untrusted_data, (bytes, ctypes.Array)):
        return hexlify(untrusted_data=(untrusted_data[:maxsize] if maxsize
            else untrusted_data))
    return untrusted_data

def hexlify_with_parition(data, *lengths):
    '''Do a little hexdump, with spaces between fields'''
    offsets = tuple(itertools.chain(
        (0,), itertools.accumulate(lengths), (len(data),)))
    return ' '.join(map(hexlify, filter(bool,
        (data[offsets[i]:offsets[i+1]] for i in range(len(offsets) - 1)))))

class SystemDNotifyProtocol(asyncio.DatagramProtocol):
    """Protocol for talking to that init replacement.

    >>> transport, protocol = await loop.create_datagram_endpoint(
    ...     SystemDNotifyProtocol,
    ...     sock=socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
    >>> protocol.notify(ready=1, status='started')
    >>> transport.close()

    If `NOTIFY_SOCKET` environment variable is not set (meaning we are not
    running under that particular init replacement), the protocol silently does
    nothing. No validation is performed on the messages.
    """
    def __init__(self):
        self.transport = None

        try:
            addr = os.environ['NOTIFY_SOCKET']
        except KeyError:
            self.addr = None
        else:
            if addr[0] == '@':
                addr = '\0' + addr[1:]
            self.addr = addr

    def connection_made(self, transport):
        # pylint: disable=missing-docstring
        self.transport = transport

    def notify(self, **kwargs):
        """Send some messages

        *kwargs* are sent, with the keyword turned to uppercase.
        """
        if self.addr is None:
            return
        for k, v in kwargs.items():
            self.transport.sendto( # type: ignore
                f'{k.upper()}={v}'.encode('utf-8'), self.addr)

async def systemd_notify(**kwargs):
    """Send a message to certain init replacement

    >>> systemd_notify(ready=1, status='started')

    If no messages are specified, a single `READY=1` message is sent.

    .. seealso:: :manpage:`sd_notify(3)`
    """

    if not kwargs:
        kwargs = {'READY': 1}
    loop = asyncio.get_running_loop()

    try:
        transport, protocol = await loop.create_datagram_endpoint(
            SystemDNotifyProtocol,
            sock=socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
    except KeyError:
        return

    protocol.notify(**kwargs)
    transport.close()


def qrexec_arg(key_handle):
    """Argument for qrexec call to identify the key"""
    # use first 128 bits of SHA-256, or 32 hexadecimal digits
    return hashlib.sha256(key_handle).hexdigest()[:32]


def int_to_bytes(num):
    """Helper method to write integer as bytes"""
    return num.to_bytes((num.bit_length() + 7) // 8, "big")
