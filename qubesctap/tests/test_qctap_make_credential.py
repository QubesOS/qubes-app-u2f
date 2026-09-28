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
import sys
from unittest.mock import patch

import pytest

from qubesctap.protocol import InvalidRequest
from qubesctap.sys_usb import qctap_make_credential
from qubesctap.tests.conftest import (
    mocked_stdio, get_response, get_request_bytes)


@patch('qubesctap.sys_usb.qctap_make_credential.qrexec_register_argument')
@pytest.mark.parametrize(
    "action",
    ("MakeCredential", "Register", "CtapError")
)
def test_key_handle_match(_mock_qrexec_register_argument, action):
    response = get_response(action)
    muxed = None

    async def mux(req):
        nonlocal muxed
        muxed = req
        return response

    with mocked_stdio(get_request_bytes("MakeCredential")):
        retcode = qctap_make_credential.main(mux)
        assert retcode in (None, 0) # main function failed
        assert not sys.stdout.buffer.getvalue()

    assert not isinstance(muxed.data, InvalidRequest)


@patch('qubesctap.sys_usb.qctap_make_credential.qrexec_register_argument')
def test_rejects_non_registration(_mock_qrexec_register_argument):
    muxed = None

    async def mux(req):
        nonlocal muxed
        muxed = req
        return get_response("CtapError")

    with mocked_stdio(get_request_bytes("GetAssertion")):
        qctap_make_credential.main(mux)

    assert isinstance(muxed.data, InvalidRequest)
