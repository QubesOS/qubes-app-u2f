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

'''Miscellaneous utilities.'''

import asyncio
import binascii
import ctypes
import os

class raw_data(object):
    '''Accessor for ctypes' byte arrays in structures.

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
    '''
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
                'value too long (should be at most {} bytes)'.format(sizeof))

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
    '''Read 16-bit unsigned integer with network byte order

    It is not an error to pass buffer longer than 2 octets.

    :param bytes buffer: the buffer
    :param int offset: the offset into the buffer
    '''
    return (buffer[offset] << 8) + (buffer[offset + 1])

def u16n_write(value):
    '''Return network byte order representation of 16-bit unsigned integer

    If the value is greater than 0xFFFF (65535) it silently overflows. This is
    on purpose, for use in Le.
    '''
    return bytes(((value >> 8) & 0xff, value & 0xff))

def hexlify(untrusted_data):
    '''A slightly better version of :py:func:`binascii.hexlify()`'''
    return binascii.hexlify(untrusted_data).decode('ascii')

def maybe_hexlify(untrusted_data, maxsize=None):
    '''Hexlify if argument is of type :class:`bytes` or :class:`ctypes.Array`'''
    if isinstance(untrusted_data, (bytes, ctypes.Array)):
        return hexlify(untrusted_data=(untrusted_data[:maxsize] if maxsize
            else untrusted_data))
    return untrusted_data

async def systemd_notify(msg='READY=1'):
    '''Send a message to certain init replacement

    :param str msg: the message
    '''
    path = os.getenv('NOTIFY_SOCKET')
    if path is None:
        return
    if path[0] == '@':
        path = '\0' + path[1:]
    reader, writer = await asyncio.open_unix_connection(path)
    writer.write(msg.encode())
    writer.close()
    reader.close()
