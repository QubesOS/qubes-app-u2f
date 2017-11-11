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

import asyncio
import pathlib
import unittest

from .. import proto
from .. import uhid
from .. import tests
from ..tools import qu2f_proxy

TEST_HID_NAME = 'Qubes U2F test device'
TEST_HID_BUS = uhid.BUS.BLUETOOTH

class TC_00_Tools_Proxy(unittest.TestCase):
    @staticmethod
    def list_hidraw_devices():
        return set(pathlib.Path('/dev').glob('hidraw*'))

    def test_000_hidraw_permissions(self):
        # regression test for #2
        loop = asyncio.get_event_loop()

        existing_hidraw = self.list_hidraw_devices()
        device = qu2f_proxy.U2FHIDQrexecDevice('sys-usb',
            name=TEST_HID_NAME,
            bus=TEST_HID_BUS,
            loop=loop)

        loop.run_until_complete(device.open())
        try:
            new_hidraw = self.list_hidraw_devices() - existing_hidraw
            self.assertEqual(len(new_hidraw), 1)
            new_hidraw = new_hidraw.pop()
            self.assertEqual(new_hidraw.stat().st_mode & 0o777, 0o660,
                'hidraw device file has incorect permissions')  # 0o660
        finally:
            loop.run_until_complete(device.close())

    def test_001_qrexec_policy_deny(self):
        denying_device = qu2f_proxy.U2FHIDQrexecDevice('sys-usb')
        denying_device.qrexec_client = '/bin/false'
        loop = asyncio.get_event_loop()

        with self.assertRaises(proto.APDUExecutionError):
            loop.run_until_complete(denying_device.handle_u2f_register(
                tests.get_capdu_register()))
        with self.assertRaises(proto.APDUExecutionError):
            loop.run_until_complete(denying_device.handle_u2f_authenticate(
                tests.get_capdu_authenticate()))

        # device.handle_u2f_version() does not return an error,
        # because response is generated locally
