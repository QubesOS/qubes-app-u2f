# coding=utf-8
#
# The Qubes OS Project, http://www.qubes-os.org
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
import pytest

from qubesu2f.protocol import ApduResponseWrapper, CborResponseWrapper, \
    InvalidCommandError, RequestWrapper
from qubesu2f.tests.conftest import get_response_bytes, \
    get_response_class, get_request_bytes, get_request_class, get_qrexec_arg


@pytest.mark.parametrize("action", ("Register", "Authenticate",))
def test_apdu_response_wrapper(action):
    expected = get_response_bytes(action)
    response = ApduResponseWrapper.from_bytes(
        expected, expected_type=get_response_class(action))
    actual = bytes(response)
    assert response.is_ok
    assert actual == expected
    try:
        assert response.qrexec_arg == get_qrexec_arg(action)
    except InvalidCommandError:
        if action == 'MakeCredential':
            raise


@pytest.mark.parametrize("action", ("Register","Authenticate",))
def test_apdu_response_wrapper_fail(action):
    expected = get_response_bytes("ApduError")
    response = ApduResponseWrapper.from_bytes(
        expected, expected_type=get_response_class(action))
    actual = bytes(response)
    assert not response.is_ok
    assert actual == b'i\x85'


@pytest.mark.parametrize(
    "action", ("GetInfo", "GetAssertion", "MakeCredential", "ClientPIN"))
def test_cbor_response_wrapper(action):
    expected = get_response_bytes(action)
    response = CborResponseWrapper.from_bytes(
        expected, expected_type=get_response_class(action))
    actual = bytes(response)

    assert response.is_ok
    assert actual == expected
    try:
        assert response.qrexec_arg == get_qrexec_arg(action)
    except InvalidCommandError:
        if action == 'MakeCredential':
            raise


@pytest.mark.parametrize(
    "action", ("GetInfo", "GetAssertion", "MakeCredential", "ClientPIN")
)
def test_cbor_response_wrapper_fail(action):
    expected = get_response_bytes("CtapError")
    response = CborResponseWrapper.from_bytes(
        expected, expected_type=get_response_class(action))
    actual = bytes(response)
    assert not response.is_ok
    assert actual == b'\x01'


@pytest.mark.parametrize(
    "action",
    ("GetInfo", "MakeCredential", "GetAssertion", "ClientPIN",
     "Register", "Authenticate",)
)
def test_cbor_request_wrapper(action):
    expected = get_request_bytes(action)
    request = RequestWrapper.from_bytes(expected)
    actual = bytes(request)
    assert actual == expected
    assert isinstance(request.data, get_request_class(action))