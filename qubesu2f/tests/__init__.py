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

'''Test suite for proxy, endpoints, browsers and some general U2F stuff.'''

import contextlib
import io
import os
import sys

from .. import const
from .. import proto
from .. import util

@contextlib.contextmanager
def mocked_stdio(stdin=b''):
    '''Context which substitutes :obj:`sys.stdin` and :obj:`sys.stdout`

    Within the context, each of them is a :class:`io.TextIOWrapper` over
    :class:`io.BytesIO`. You may pass an initial state of stdin as an argument.
    Retrieve stdout from ``sys.stdin.buffer.getvalue()``.

    >>> with mocked_stdio(b'spam'):
    ...     print('eggs')
    ...     assert sys.stdin.read() == 'spam'
    ...     assert sys.stdout.buffer.getvalue() == b'eggs'
    '''

    sys.stdin = io.TextIOWrapper(io.BytesIO(stdin))
    sys.stdout = io.TextIOWrapper(io.BytesIO(), write_through=True)
    try:
        yield
    finally:
        sys.stdin = sys.__stdin__
        sys.stdout = sys.__stdout__

def get_capdu_register(appid=None, p1=const.U2F_AUTH.ENFORCE):
    '''Get command APDU for U2F_REGISTER with random nonce and appid'''
    nonce = os.urandom(const.U2F_NONCE_SIZE)
    appid = appid or os.urandom(const.U2F_APPID_SIZE)

    return proto.CommandAPDURegister(
        untrusted_cla=0,
        untrusted_ins=const.U2F.REGISTER,
        untrusted_p1=p1,
        untrusted_p2=0,
        untrusted_request_data=nonce+appid,
        untrusted_le=0x10000)

def get_capdu_authenticate(appid=None, key_handle=None,
        p1=const.U2F_AUTH.ENFORCE):
    '''Get command APDU for U2F_AUTHENTICATE

    If either *appid* or *key_handle* is not specified, it is randomised.
    '''
    nonce = os.urandom(const.U2F_NONCE_SIZE)
    appid = appid or os.urandom(const.U2F_APPID_SIZE)
    key_handle = key_handle or os.urandom(0x40)  # length is from Yubico 4

    return proto.CommandAPDUAuthenticate(
        untrusted_cla=0,
        untrusted_ins=const.U2F.AUTHENTICATE,
        untrusted_p1=p1,
        untrusted_p2=0,
        untrusted_request_data=nonce+appid+bytes((len(key_handle),))+key_handle,
        untrusted_le=0x10000)
