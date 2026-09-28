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
from qubesctap.protocol import CborRequestWrapper, InvalidRequest
from qubesctap.sys_usb import qctap_get_assertion
from qubesctap.tests.conftest import (
    mocked_stdio, get_qrexec_arg, get_request, get_request_bytes)


@pytest.mark.parametrize("action", ("GetAssertion", "Authenticate"))
def test_key_handle_match(action):
    request = get_request(action)
    argument = get_qrexec_arg(action)
    muxed = None

    async def mux(req):
        nonlocal muxed
        muxed = req

    with mocked_stdio(bytes(request)):
        retcode = qctap_get_assertion.main([argument], mux=mux)
        assert retcode in (None, 0)
        assert not sys.stdout.buffer.getvalue()

    assert not isinstance(muxed.data, InvalidRequest)
    assert list(muxed.qrexec_args) == [argument]


@pytest.mark.parametrize("action", ("GetAssertion", "Authenticate"))
def test_key_handle_mismatch(action):
    request = get_request(action)
    false_argument = str(reversed(get_qrexec_arg(action)))
    muxed = None

    async def mux(req):
        nonlocal muxed
        muxed = req

    with mocked_stdio(bytes(request)):
        qctap_get_assertion.main([false_argument], mux=mux)

    assert isinstance(muxed.data, InvalidRequest)


@pytest.mark.parametrize("argv", ([], [""]))
def test_missing_argument_fails_closed(argv):
    request = get_request("GetAssertion")
    muxed = None

    async def mux(req):
        nonlocal muxed
        muxed = req

    with mocked_stdio(bytes(request)):
        qctap_get_assertion.main(argv, mux=mux)

    assert isinstance(muxed.data, InvalidRequest)


def test_restricted_to_authorised_credential():
    request = get_request("GetAssertion")
    argument = get_qrexec_arg("GetAssertion")

    other_cred = {"type": "public-key", "id": b"\xaa" * 32}
    data = request.data
    trimmed_data_dict = {k: v for k, v in data.__dict__.items()
                         if not k.startswith("_")}
    trimmed_data_dict["allow_list"] = list(data.allow_list) + [other_cred]
    extended = CborRequestWrapper(GetAssertion(**trimmed_data_dict))

    assert len(list(extended.qrexec_args)) == 2

    muxed = None

    async def mux(req):
        nonlocal muxed
        muxed = req

    with mocked_stdio(bytes(extended)):
        retcode = qctap_get_assertion.main([argument], mux=mux)
        assert retcode in (None, 0)

    assert list(muxed.qrexec_args) == [argument]


def test_rejects_non_assertion():
    muxed = None

    async def mux(req):
        nonlocal muxed
        muxed = req

    with mocked_stdio(get_request_bytes("MakeCredential")):
        qctap_get_assertion.main([get_qrexec_arg("GetAssertion")], mux=mux)

    assert isinstance(muxed.data, InvalidRequest)
