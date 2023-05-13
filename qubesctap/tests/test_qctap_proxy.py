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

from qubesctap.client import uhid, qctap_proxy
from qubesctap.tests.conftest import get_request, \
    get_response_bytes, get_response_class, FakeQrexecClient

TEST_HID_NAME = 'Qubes CTAP test device'
TEST_HID_BUS = uhid.BUS.BLUETOOTH


@patch('asyncio.create_subprocess_exec')
@pytest.mark.parametrize(
    "action",
    ("GetInfo", "GetAssertion", "MakeCredential", "ClientPIN"),
)
def test_handle_fido2(mock_subprocess, action):
    expected = get_response_bytes(action)
    mock_subprocess.return_value = FakeQrexecClient(stdout=expected)

    loop = asyncio.get_event_loop()

    device = qctap_proxy.CTAPHIDQrexecDevice('sys-usb',
                                             name=TEST_HID_NAME,
                                             bus=TEST_HID_BUS,
                                             loop=loop)

    request = get_request(action)
    handler = getattr(device, "handle_fido2_" + request.name)
    response = loop.run_until_complete(handler(request))
    assert isinstance(response.data, get_response_class(action))
    assert response.is_ok
    assert bytes(response) == expected

