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

import pytest

from qubesctap.ctap2 import GetAssertion
from qubesctap.protocol import CborRequestWrapper, RequestWrapper
from qubesctap.sys_usb import qctap_get_assertion
from qubesctap.tests.conftest import mocked_stdio, get_qrexec_arg, get_request


@pytest.mark.parametrize(
    "action",
    ("GetAssertion", "Authenticate",)
)
def test_key_handle_match(action):
    request = get_request(action)
    argument = get_qrexec_arg(action)

    apdu_muxed = False

    async def mux(apdu):
        nonlocal apdu_muxed
        apdu_muxed = bytes(apdu) == bytes(request)

    with mocked_stdio(bytes(request)):
        retcode = qctap_get_assertion.main([argument], mux=mux)
        assert retcode in (None, 0) # main function failed
        assert not sys.stdout.buffer.getvalue()
        assert apdu_muxed


@pytest.mark.parametrize(
    "action",
    ("GetAssertion", "Authenticate",)
)
def test_key_handle_mismatch(action):
    request = get_request(action)
    argument = get_qrexec_arg(action)
    false_argument = str(reversed(argument))
    assert argument != false_argument

    apdu_muxed = False

    async def mux(apdu):
        nonlocal request, apdu_muxed
        apdu_muxed = bytes(apdu) == bytes(request)

    with mocked_stdio(bytes(request)):
        retcode = qctap_get_assertion.main([false_argument], mux=mux)
        assert retcode > 0 or sys.stdout.buffer.getvalue()[0] & 0xf0 == 0x60
        assert not apdu_muxed


def test_allow_list_is_trimmed():
    request = get_request("GetAssertion")
    argument = get_qrexec_arg("GetAssertion")

    other_cred = {"type": "public-key", "id": b"\xaa" * 32}
    data = request.data
    trimmed_data_dict = {k: v for k, v in data.__dict__.items()
                         if not k.startswith("_")}
    trimmed_data_dict["allow_list"] = list(data.allow_list) + [other_cred]
    extended = CborRequestWrapper(GetAssertion(**trimmed_data_dict))

    assert len(list(extended.qrexec_args)) == 2
    assert argument in list(extended.qrexec_args)

    muxed_args = None

    async def mux(request_bytes):
        nonlocal muxed_args
        muxed_args = list(
            RequestWrapper.from_bytes(bytes(request_bytes)).qrexec_args)

    with mocked_stdio(bytes(extended)):
        retcode = qctap_get_assertion.main([argument], mux=mux)
        assert retcode in (None, 0)

    assert muxed_args == [argument]
