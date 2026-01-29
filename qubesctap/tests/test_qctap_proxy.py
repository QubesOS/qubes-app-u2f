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
from unittest.mock import patch

import pytest
import asyncio
import signal
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fido2.ctap1 import APDU, ApduError
from fido2.ctap2 import Ctap2

import qubesctap.client.qctap_proxy as entry
from qubesctap.client import uhid, qctap_proxy
from qubesctap.protocol import CborResponseWrapper, RequestWrapper
from qubesctap.tests.conftest import get_request, \
    get_response_bytes, get_response_class, FakeQrexecClient

TEST_HID_NAME = 'Qubes CTAP test device'
TEST_HID_BUS = uhid.BUS.BLUETOOTH


@patch('asyncio.create_subprocess_exec')
@pytest.mark.parametrize(
    "action",
    ("GetInfo", "GetAssertion", "MakeCredential", "ClientPIN"),
)
@pytest.mark.asyncio
async def test_handle_fido2(mock_subprocess, action):
    expected = get_response_bytes(action)
    mock_subprocess.return_value = FakeQrexecClient(stdout=expected)

    device = qctap_proxy.CTAPHIDQrexecDevice(
        'sys-usb',
        name=TEST_HID_NAME,
        bus=TEST_HID_BUS,
    )

    request = get_request(action)
    handler = getattr(device, "handle_fido2_" + request.name)
    response = await handler(request)

    assert isinstance(response.data, get_response_class(action))
    assert response.is_ok
    assert bytes(response) == expected

@pytest.mark.asyncio
async def test_pin_allowed_denied_use_not_satisfied(monkeypatch):
    dev = qctap_proxy.CTAPHIDQrexecDevice("some-vm", name="x")

    async def fake_qrexec(_req, rpcname: str):
        assert rpcname == "ctap.ClientPin"
        raise ApduError(APDU.USE_NOT_SATISFIED)

    monkeypatch.setattr(dev, "qrexec_transaction", fake_qrexec)

    allowed = await dev._pin_allowed()
    assert allowed is False

@pytest.mark.asyncio
async def test_pin_allowed_true(monkeypatch):
    dev = qctap_proxy.CTAPHIDQrexecDevice("some-vm", name="x")

    async def fake_qrexec(_req, rpcname: str):
        assert rpcname == "ctap.ClientPin"
        return b"\x00\xa0"  # a valid-ish "success" response (status 0 + empty map)

    monkeypatch.setattr(dev, "qrexec_transaction", fake_qrexec)

    allowed = await dev._pin_allowed()
    assert allowed is True

@pytest.mark.asyncio
async def test_modify_info_removes_pin_protocols(monkeypatch):
    dev = qctap_proxy.CTAPHIDQrexecDevice("some-vm", name="x")

    class FakeInfo(dict):
        @staticmethod
        def from_dict(d):
            return FakeInfo(d)

    # Patch ctap2.Info used inside qctap_proxy
    monkeypatch.setattr(qctap_proxy.ctap2, "Info", FakeInfo)

    wrapped = CborResponseWrapper(FakeInfo({0x01: "x", 0x06: [1, 2]}))
    dev._modify_info(wrapped)

    assert 0x06 not in wrapped.data
    assert wrapped.data[0x01] == "x"

@pytest.mark.asyncio
async def test_handle_fido2_get_info_modifies_info_when_pin_disabled(monkeypatch):
    dev = qctap_proxy.CTAPHIDQrexecDevice("some-vm", name="x")

    # Make the response parse into our FakeInfo mapping.
    class FakeInfo(dict):
        @staticmethod
        def from_dict(d):
            return FakeInfo(d)

    monkeypatch.setattr(qctap_proxy.ctap2, "Info", FakeInfo)

    from fido2 import cbor
    info_bytes = b"\x00" + cbor.encode({0x01: "x", 0x06: [1]})

    async def fake_qrexec(_req, rpcname: str):
        assert rpcname == "ctap.GetInfo"
        return info_bytes

    monkeypatch.setattr(dev, "qrexec_transaction", fake_qrexec)
    monkeypatch.setattr(dev, "_pin_allowed", AsyncMock(return_value=False))

    req = RequestWrapper.from_bytes(chr(Ctap2.CMD.GET_INFO).encode())
    resp = await dev.handle_fido2_get_info(req)

    # Don't assert resp.is_ok here; FakeInfo isn't in protocol.CTAP2_ACCEPTABLE_RESPONSES
    assert 0x06 not in resp.data
    assert resp.data[0x01] == "x"

@pytest.mark.asyncio
async def test_handle_fido2_get_assertion_retries(monkeypatch):
    dev = qctap_proxy.CTAPHIDQrexecDevice("some-vm", name="x")

    class FakeReq:
        qrexec_args = ["aaa", "bbb"]

    calls = {"n": 0}

    async def fake_qrexec(_req, rpcname: str):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("first attempt fails")
        assert rpcname == "u2f.Authenticate+bbb"
        return b"\x00\xa0"  # dummy bytes; we'll bypass parsing anyway

    monkeypatch.setattr(dev, "qrexec_transaction", fake_qrexec)

    sentinel = object()

    # Patch parsing to avoid constructing a real fido2.AssertionResponse
    monkeypatch.setattr(
        qctap_proxy.CborResponseWrapper,
        "from_bytes",
        staticmethod(lambda _b, expected_type=None: sentinel),
    )

    resp = await dev.handle_fido2_get_assertion(FakeReq())
    assert resp is sentinel
    assert calls["n"] == 2

@pytest.mark.asyncio
async def test_main_installs_signal_fallback_and_shuts_down(monkeypatch):
    # Fake args returned by parser.parse_args
    fake_args = SimpleNamespace(
        vmname="some-vm",
        hid_name="n",
        hid_phys=None,
        hid_serial=None,
        hid_vendor=0,
        hid_product=0,
        hid_version=0,
        hid_bus=None,
        hid_country=None,
        hid_rdesc=b"",
        loglevel=[0],
    )
    monkeypatch.setattr(qctap_proxy.parser, "parse_args", lambda _args=None: fake_args)

    # Fake device with open/close
    fake_device = Mock()
    fake_device.open = AsyncMock()
    fake_device.close = AsyncMock()

    monkeypatch.setattr(qctap_proxy, "CTAPHIDQrexecDevice", lambda *a, **k: fake_device)
    monkeypatch.setattr(qctap_proxy.util, "systemd_notify", AsyncMock())

    # Force NotImplementedError branch
    fake_loop = Mock()
    fake_loop.add_signal_handler.side_effect = NotImplementedError
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: fake_loop)

    # Capture signal handlers registered via signal.signal fallback
    registered = {}
    def fake_signal(sig, handler):
        registered[sig] = handler

    monkeypatch.setattr(signal, "signal", fake_signal)

    # Run main in a task so we can trigger shutdown
    task = asyncio.create_task(qctap_proxy.main_async([]))

    # Allow it to reach stop_event.wait()
    await asyncio.sleep(0)

    assert signal.SIGINT in registered
    assert signal.SIGTERM in registered

    # Trigger shutdown by calling the registered handler as signal would.
    registered[signal.SIGINT](signal.SIGINT, None)

    await task

    fake_device.open.assert_awaited()
    fake_device.close.assert_awaited()



def test_main_calls_asyncio_run(monkeypatch):
    # Make main_async return a sentinel object (doesn't have to be a real coroutine
    # because we're not going to actually run it).
    sentinel = object()
    monkeypatch.setattr(entry, "main_async", Mock(return_value=sentinel))

    run_mock = Mock()
    monkeypatch.setattr(entry.asyncio, "run", run_mock)

    entry.main()

    entry.main_async.assert_called_once_with(None)
    run_mock.assert_called_once_with(sentinel)