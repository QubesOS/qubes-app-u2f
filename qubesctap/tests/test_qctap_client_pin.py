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
import io
import sys
from dataclasses import replace

import pytest
from fido2.ctap2.pin import ClientPin

from qubesctap.ctap2 import ClientPIN
from qubesctap.protocol import CborRequestWrapper, InvalidRequest
from qubesctap.sys_usb import qctap_client_pin
from qubesctap.sys_usb.mux import mux as real_mux
from qubesctap.tests.conftest import (
    mocked_stdio, get_request, get_request_bytes)


def run(request_bytes, argv, retcode=0):
    muxed = None

    async def mux(req):
        nonlocal muxed
        muxed = req

    with mocked_stdio(request_bytes):
        assert qctap_client_pin.main(argv, mux=mux) == retcode
        assert not sys.stdout.buffer.getvalue()
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
    """No argument: nothing reaches the key and the reply is empty."""
    assert run(get_request_bytes("ClientPIN"), argv, retcode=1) is None


@pytest.mark.parametrize("sub_cmd", (8, 0x40, True))
def test_unknown_subcommand_refused(sub_cmd):
    """Unknown, bool or non-int subcommand is refused."""
    data = replace(get_request("ClientPIN").data, sub_cmd=sub_cmd)
    muxed = run(bytes(CborRequestWrapper(data)), ["get-pin-retries"])
    assert isinstance(muxed.data, InvalidRequest)


def test_mismatch_reply():
    """Refused request gets an INVALID_COMMAND reply, not a device call."""
    response = None

    async def mux(req):
        nonlocal response
        response = await real_mux(req, stream=io.BytesIO(), devices=[])

    data = replace(get_request("ClientPIN").data,
                   sub_cmd=int(ClientPin.CMD.SET_PIN))
    with mocked_stdio(bytes(CborRequestWrapper(data))):
        assert qctap_client_pin.main(["get-pin-retries"], mux=mux) == 0
    assert bytes(response) == b'\x01'


def test_rejects_non_client_pin():
    """Request other than ClientPIN is refused."""
    muxed = run(get_request_bytes("GetInfo"), ["get-pin-retries"])
    assert isinstance(muxed.data, InvalidRequest)


@pytest.mark.parametrize("sub_cmd, arg", (
    (0x01, "get-pin-retries"),
    (0x02, "get-key-agreement"),
    (0x03, "set-pin"),
    (0x04, "change-pin"),
    (0x05, "get-token-using-pin-legacy"),
    (0x06, "get-token-using-uv"),
    (0x07, "get-uv-retries"),
    (0x09, "get-token-using-pin"),
    (8, None),
    (True, None),
))
def test_qrexec_arg_names(sub_cmd, arg):
    """Subcommand maps to the documented qrexec argument."""
    data = replace(get_request("ClientPIN").data, sub_cmd=sub_cmd)
    assert data.qrexec_arg == arg
