# coding=utf-8
#
# The Qubes OS Project, https://www.qubes-os.org
#
# Copyright (C) 2026  Alex Mazzariol <alex@alex-maz.info>
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
import ctypes
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fido2.ctap import CtapError

from qubesctap.client import hidemu
from qubesctap import const


def _mk_init_packet(cid: int, cmd: int, payload: bytes) -> "hidemu.qubesctap.client.hid_data.CTAPHIDPacket":
    pkt = hidemu.qubesctap.client.hid_data.CTAPHIDPacket(cid=cid)
    pkt.init.type = const.CTAPHID_TYPE.INIT
    pkt.init.cmd = cmd
    pkt.init.bcnt = len(payload)
    # write first chunk of data
    chunk = ctypes.sizeof(pkt.init.data)
    ctypes.memmove(pkt.init.data, payload, min(len(payload), chunk))
    return pkt

def test_channel_init_cont_execute_roundtrip():
    ch = hidemu.CTAPHIDChannel(cid=1)

    called = {}
    def cb(cid, data):
        called["cid"] = cid
        called["data"] = data
        return b"ok"

    payload = b"ABCDEFGH1234"
    init_pkt = SimpleNamespace(bcnt=len(payload), data=(ctypes.c_uint8 * const.HID_FRAME_SIZE)())  # dummy struct-ish
    # Put as much as fits in first fragment:
    ctypes.memmove(init_pkt.data, payload, min(len(payload), ctypes.sizeof(init_pkt.data)))

    ch.init(init_pkt, cb)

    assert ch.is_finished()
    ret = ch.execute()
    assert ret == b"ok"
    assert called["cid"] == 1
    assert called["data"].startswith(b"ABCDEFGH")

def test_channel_cont_wrong_seq_raises():
    ch = hidemu.CTAPHIDChannel(cid=1)

    cb = Mock(return_value=b"ok")

    payload = b"X" * 100
    init_pkt = SimpleNamespace(bcnt=len(payload), data=(ctypes.c_uint8 * const.HID_FRAME_SIZE)())
    ctypes.memmove(init_pkt.data, payload, min(len(payload), ctypes.sizeof(init_pkt.data)))
    ch.init(init_pkt, cb)

    cont_pkt = SimpleNamespace(seq=5, data=(ctypes.c_uint8 * const.HID_FRAME_SIZE)())
    with pytest.raises(CtapError) as e:
        ch.cont(cont_pkt)

    assert e.value.code == CtapError.ERR.INVALID_SEQ
    cb.assert_not_called()


def test_channel_busy_on_reinit():
    ch = hidemu.CTAPHIDChannel(cid=1)

    cb = Mock(return_value=b"ok")

    payload = b"1234"
    init_pkt = SimpleNamespace(bcnt=len(payload), data=(ctypes.c_uint8 * const.HID_FRAME_SIZE)())
    ctypes.memmove(init_pkt.data, payload, len(payload))
    ch.init(init_pkt, cb)

    # Second init without completing should raise CHANNEL_BUSY
    with pytest.raises(CtapError) as e:
        ch.init(init_pkt, cb)
    assert e.value.code == CtapError.ERR.CHANNEL_BUSY
    cb.assert_not_called()


@pytest.mark.asyncio
async def test_handle_hid_output_invalid_command_schedules_error(monkeypatch):
    """
    Feed an INIT packet with an invalid CTAPHID command byte and ensure
    write_ctap_error is scheduled.
    """
    dev = hidemu.CTAPHIDDevice()

    created = []
    orig_create_task = asyncio.create_task

    def fake_create_task(coro):
        created.append(coro)
        return orig_create_task(coro)

    monkeypatch.setattr(asyncio, "create_task", fake_create_task)

    dev.write_ctap_error = AsyncMock()

    cid = int(hidemu.CTAPHID_CID.BROADCAST)
    bad_cmd = 0x7F  # not a valid CTAPHID command
    pkt = _mk_init_packet(cid=cid, cmd=bad_cmd, payload=b"")

    class Out:
        size = const.HID_FRAME_SIZE
        data = (ctypes.c_uint8 * hidemu.uhid.UHID_DATA_MAX)()

    pkt_bytes = bytes(pkt)
    ctypes.memmove(Out.data, pkt_bytes, len(pkt_bytes))
    event = SimpleNamespace(output=Out)

    dev.handle_hid_output(event)

    # Let the scheduled task run
    await asyncio.sleep(0)

    assert created, "Expected a task to be scheduled"
    dev.write_ctap_error.assert_awaited()


def test_create_new_channel_unique(monkeypatch):
    dev = hidemu.CTAPHIDDevice()

    # Force os.urandom to return BROADCAST first, then a new value
    seq = [b"\xff\xff\xff\xff", b"\x00\x00\x00\x01"]
    monkeypatch.setattr(hidemu.os, "urandom", lambda n: seq.pop(0))

    new_cid = dev.create_new_channel()
    assert new_cid != int(hidemu.CTAPHID_CID.BROADCAST)
    assert new_cid in dev.channels


@pytest.mark.asyncio
async def test_handle_hid_output_finished_channel_schedules_execute(monkeypatch):
    dev = hidemu.CTAPHIDDevice()

    # Prevent the scheduled handler from doing real IO
    dev.write_ctaphid_response = AsyncMock()

    # Spy on create_task and on channel.execute
    created = []
    orig_create_task = asyncio.create_task

    def fake_create_task(coro):
        created.append(coro)
        return orig_create_task(coro)

    monkeypatch.setattr(asyncio, "create_task", fake_create_task)

    cid = int(hidemu.CTAPHID_CID.BROADCAST)
    channel = dev.channels[cid]
    channel.execute = Mock(wraps=channel.execute)

    # Build a valid INIT packet for CTAPHID.PING with a 1-byte payload.
    # bcnt must be > 0; 1 byte fits in the init fragment, so the channel finishes immediately.
    payload = b"A"
    pkt = hidemu.qubesctap.client.hid_data.CTAPHIDPacket(cid=cid)
    pkt.init.type = const.CTAPHID_TYPE.INIT
    pkt.init.cmd = int(hidemu.CTAPHID.PING)
    pkt.init.bcnt = len(payload)
    ctypes.memmove(pkt.init.data, payload, len(payload))

    # Wrap into a fake UHID output event like other tests do
    class Out:
        size = const.HID_FRAME_SIZE
        data = (ctypes.c_uint8 * hidemu.uhid.UHID_DATA_MAX)()

    pkt_bytes = bytes(pkt)
    ctypes.memmove(Out.data, pkt_bytes, len(pkt_bytes))
    event = SimpleNamespace(output=Out)

    dev.handle_hid_output(event)

    # Let scheduled tasks run
    await asyncio.sleep(0)

    # The finished-channel branch should have fired
    channel.execute.assert_called_once()
    assert created, "Expected at least one asyncio task to be scheduled"

    # And since PING handler should run, it should try to write a response
    dev.write_ctaphid_response.assert_awaited()