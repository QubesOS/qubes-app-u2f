# coding=utf-8
#
# The Qubes OS Project, https://www.qubes-os.org
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
from dataclasses import replace

import pytest
from fido2.ctap2.pin import ClientPin

from qubesctap.ctap2 import ClientPIN
from qubesctap.protocol import CborRequestWrapper, InvalidRequest
from qubesctap.sys_usb import qctap_client_pin
from qubesctap.tests.conftest import (
    mocked_stdio, get_request, get_request_bytes)


def run(request_bytes, argv):
    muxed = None

    async def mux(req):
        nonlocal muxed
        muxed = req

    with mocked_stdio(request_bytes):
        qctap_client_pin.main(argv, mux=mux)
    return muxed


def test_subcommand_match():
    """Request is passed on when the argument names its subcommand."""
    request = get_request("ClientPIN")
    muxed = run(bytes(request), ["get-token-using-pin-legacy"])
    assert isinstance(muxed.data, ClientPIN)
    assert bytes(muxed) == bytes(request)


def test_subcommand_mismatch():
    """setPIN request is refused when only get-pin-retries is allowed."""
    data = replace(get_request("ClientPIN").data,
                   sub_cmd=int(ClientPin.CMD.SET_PIN))
    muxed = run(bytes(CborRequestWrapper(data)), ["get-pin-retries"])
    assert isinstance(muxed.data, InvalidRequest)


@pytest.mark.parametrize("argv", ([], [""]))
def test_missing_argument_fails_closed(argv):
    """Request without a qrexec argument is refused."""
    muxed = run(get_request_bytes("ClientPIN"), argv)
    assert isinstance(muxed.data, InvalidRequest)


def test_rejects_non_client_pin():
    """Request other than ClientPIN is refused."""
    muxed = run(get_request_bytes("GetInfo"), ["get-pin-retries"])
    assert isinstance(muxed.data, InvalidRequest)


@pytest.mark.parametrize("sub_cmd, arg", (
    (ClientPin.CMD.GET_PIN_RETRIES, "get-pin-retries"),
    (ClientPin.CMD.SET_PIN, "set-pin"),
    (ClientPin.CMD.CHANGE_PIN, "change-pin"),
    (ClientPin.CMD.GET_TOKEN_USING_PIN, "get-token-using-pin"),
    (8, "subcmd-8"),
))
def test_qrexec_arg_names(sub_cmd, arg):
    """Subcommand maps to the documented qrexec argument."""
    data = replace(get_request("ClientPIN").data, sub_cmd=int(sub_cmd))
    assert data.qrexec_arg == arg
