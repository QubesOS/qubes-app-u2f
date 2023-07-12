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

"""
Constants for CTAP protocol.
"""
# pylint: disable=invalid-name,missing-docstring

import enum

DEVICE_TIMEOUT = 5
USER_TIMEOUT = 30

HID_FRAME_SIZE = 64

# This is 7609. See [CTAPHID 11.2.4] for where it came from.
MAX_MSG_SIZE = HID_FRAME_SIZE - 7 + 0x80 * (HID_FRAME_SIZE - 5)

# Register

U2F_NONCE_SIZE = 32  # "challenge parameter"
U2F_APPID_SIZE = 32  # "application parameter"

MAX_KH_SIZE = 255


U2F_VERSION = 'U2F_V2'

CTAPHID_IF_VERSION = 2


@enum.unique
class CTAPHID_TYPE(enum.IntEnum):
    INIT = 1
    CONT = 0

QREXEC_CLIENT = '/usr/bin/qrexec-client-vm'
