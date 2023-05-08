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

# pylint: disable=missing-docstring

'''Some conformance tests to be used on tokens with suspicious provenience.'''

import os
import time
import unittest

try:
    import fido2  # pylint: disable=import-error
except ImportError:
    import u2flib_host.u2f  # pylint: disable=import-error

from .. import const
from .. import proto
from .. import tests

class TC_10_NoEnforce(unittest.TestCase):
    '''Test P1=NO_ENFORCE

    P1 octet in command APDU (by spec only for ``U2F_AUTHENTICATE``, but it is
    also set for ``U2F_REGISTER``) sets the requirement of verifying user's
    presence. When set to ``0x07`` (no enforce), token MAY not enforce user's
    presence, ie. not wait for the user to press button.

    Some tokens do not support this value and fail with weird errors when it is
    used.
    '''

    def transaction(self, capdu, wait_for_users_presence=False):
        devices = u2flib_host.u2f.list_devices()
        if len(devices) != 1:
            self.skipTest('found {} devices, but needs exactly 1')
        device = devices[0]

        for _ in range(10):  # 10 * 3 s = 30 s
            try:
                device.open()
                # pylint: disable=protected-access
                rapdu = device._do_send_apdu(bytes(capdu))
            finally:
                device.close()

            rapdu = capdu.APDU_RESPONSE.from_buffer(untrusted_data=rapdu)

            try:
                rapdu.raise_for_sw()
            except proto.APDUConditionsNotSatisfiedError:
                if not wait_for_users_presence:
                    raise
                time.sleep(3)
                continue
            else:
                break

        return rapdu


    def tests_001_register(self):
        capdu = tests.get_capdu_register(p1=const.U2F_AUTH.NO_ENFORCE)

        try:
            self.transaction(capdu)
        except proto.APDUConditionsNotSatisfiedError:
            self.fail('device does not suppor NO_ENFORCE on U2F.REGISTER')
        # if sw is 0x9000, success; if other sw, don't catch and test ERRORs

    def test_002_authenticate(self):
        '''Touch the device when it blinks'''
        appid = os.urandom(const.U2F_APPID_SIZE)
        capdu_r = tests.get_capdu_register(appid=appid)

        rapdu = self.transaction(capdu_r, wait_for_users_presence=True)

        capdu_a = tests.get_capdu_authenticate(appid=appid,
                key_handle=rapdu.key_handle,
                p1=const.U2F_AUTH.NO_ENFORCE)

        try:
            self.transaction(capdu_a)
        except proto.APDUConditionsNotSatisfiedError:
            self.fail('device does not suppor NO_ENFORCE on U2F.AUTHENTICATE')
        # if sw is 0x9000, success; if other sw, don't catch and test ERRORs
