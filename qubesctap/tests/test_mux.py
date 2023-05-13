# coding=utf-8
#
# The Qubes OS Project, https://www.qubes-os.org
#
# Copyright (C) 2023  Piotr Bartman <prbartman@invisiblethingslab.com>
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
import asyncio
from unittest.mock import patch

import pytest

from qubesctap.client import uhid
from qubesctap.protocol import RequestWrapper
from qubesctap.sys_usb.mux import mux
from qubesctap.tests.conftest import get_request, \
    get_response_bytes, mocked_stdio

TEST_HID_NAME = 'Qubes CTAP test device'
TEST_HID_BUS = uhid.BUS.BLUETOOTH


class FakeDevice:
    def __init__(self, ctap2: bool, response: bytes):
        if ctap2:
            self.capabilities = 0x04
        else:
            self.capabilities = 0x00
        self.response = response

    def call(self, cmd, data= b"", event=None, on_keepalive=None) -> bytes:
        request_name = RequestWrapper.from_bytes(data).data.__class__.__name__
        return get_response_bytes(request_name)

    def close(self):
        pass

@patch('fido2.hid.CtapHidDevice.list_devices')
@pytest.mark.parametrize(
    "action",
    ("GetInfo", "MakeCredential", "GetAssertion", "ClientPIN",
     "Register", "Authenticate", "CtapError", "ApduError")
)
def test_mux_ctap2(list_devices, action):
    request = get_request(action)
    expected_response = get_response_bytes(action)
    list_devices.return_value = (
        FakeDevice(ctap2=True, response=expected_response),
    )

    loop = asyncio.get_event_loop()

    with mocked_stdio():
        response = loop.run_until_complete(mux(bytes(request)))
        assert response.is_ok == (action not in ("CtapError", "ApduError"))


@patch('fido2.hid.CtapHidDevice.list_devices')
@pytest.mark.parametrize(
    "action",
    ("Register", "Authenticate", "ApduError")
)
def test_mux_ctap1(list_devices, action):
    request = get_request(action)
    expected_response = get_response_bytes(action)
    list_devices.return_value = (
        FakeDevice(ctap2=False, response=expected_response),
    )

    loop = asyncio.get_event_loop()

    with mocked_stdio():
        response = loop.run_until_complete(mux(bytes(request)))
        assert response.is_ok == (action != "ApduError")
