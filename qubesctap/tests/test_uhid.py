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
from unittest.mock import AsyncMock, Mock
import pytest
from types import SimpleNamespace

from qubesctap.client import uhid


@pytest.mark.asyncio
async def test_uhid_open_writes_create2_and_adds_reader(monkeypatch):
    # Fake loop
    fake_loop = Mock()
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: fake_loop)

    # Fake /dev/uhid file handle
    fake_fd = Mock()
    fake_fd.write = Mock(return_value=ctypes.sizeof(uhid.uhid_event))
    monkeypatch.setattr("builtins.open", lambda *a, **k: fake_fd)

    # Make to_thread run inline
    async def fake_to_thread(func, *args, **kwargs):
        return func(*args, **kwargs)
    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)

    dev = uhid.UHIDDevice(name="Dev", rdesc=b"\x01\x02")

    await dev.open()

    # open() should add a reader callback on the fd
    fake_loop.add_reader.assert_called_once()
    assert dev.fd is fake_fd
    assert dev._loop is fake_loop

    # and it should have attempted to write CREATE2
    assert fake_fd.write.call_count >= 1

    await dev.close()
    fake_loop.remove_reader.assert_called_once()


@pytest.mark.asyncio
async def test_write_uhid_req_sets_union_fields(monkeypatch):
    fake_fd = Mock()
    fake_fd.write = Mock(return_value=ctypes.sizeof(uhid.uhid_event))
    async def fake_to_thread(func, *args, **kwargs):
        return func(*args, **kwargs)
    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)

    dev = uhid.UHIDDevice(name="X", rdesc=b"\x00")
    dev.fd = fake_fd  # bypass open() for unit-level test

    # Exercise payload setting: CREATE2 has many fields including arrays.
    await dev.write_uhid_req(
        uhid.UHID.CREATE2,
        name=b"NAME",
        phys=b"PHYS",
        uniq=b"SERIAL",
        bus=uhid.BUS.BLUETOOTH,
        vendor=1,
        product=2,
        version=3,
        country=4,
        rd=b"\xAA\xBB",
    )

    assert fake_fd.write.call_count == 1
    written_event = fake_fd.write.call_args[0][0]
    assert isinstance(written_event, uhid.uhid_event)
    assert written_event.type == int(uhid.UHID.CREATE2)


def test_read_req_dispatches_to_handler(monkeypatch):
    # Build a uhid_event of type START with dev_flags set.
    ev = uhid.uhid_event(type=uhid.UHID.START)
    ev.start.dev_flags = int(uhid.UHID_DEV_FLAGS.NUMBERED_INPUT_REPORTS)

    # Fake fd that returns the raw bytes of that event.
    fake_fd = Mock()
    fake_fd.read = Mock(return_value=bytes(ev))

    dev = uhid.UHIDDevice()
    dev.fd = fake_fd

    # Before: flag should not be set
    assert dev.dev_flags.get(uhid.UHID_DEV_FLAGS.NUMBERED_INPUT_REPORTS) is None

    dev._read_req()

    # After: handle_hid_start should have run and populated dev_flags
    assert dev.dev_flags[uhid.UHID_DEV_FLAGS.NUMBERED_INPUT_REPORTS] is True
    assert dev.is_started.is_set()

@pytest.mark.asyncio
async def test_handle_get_report_schedules_reply(monkeypatch):
    dev = uhid.UHIDDevice()

    dev.write_uhid_req = AsyncMock()

    created = []
    def fake_create_task(coro):
        created.append(coro)
        return Mock()
    monkeypatch.setattr(asyncio, "create_task", fake_create_task)

    # Minimal event-like object that matches current handler usage: event.id
    ev = SimpleNamespace(id=123)

    dev.handle_hid_get_report(ev)

    assert created, "Expected a task to be scheduled"
    dev.write_uhid_req.assert_called_once()
    args, kwargs = dev.write_uhid_req.call_args
    assert args[0] == uhid.UHID.GET_REPORT_REPLY
    assert kwargs["id"] == 123


@pytest.mark.asyncio
async def test_handle_set_report_schedules_reply(monkeypatch):
    dev = uhid.UHIDDevice()

    dev.write_uhid_req = AsyncMock()

    created = []
    def fake_create_task(coro):
        created.append(coro)
        return Mock()
    monkeypatch.setattr(asyncio, "create_task", fake_create_task)

    ev = SimpleNamespace(id=456)

    dev.handle_hid_set_report(ev)

    assert created
    dev.write_uhid_req.assert_called_once()
    args, kwargs = dev.write_uhid_req.call_args
    assert args[0] == uhid.UHID.SET_REPORT_REPLY
    assert kwargs["id"] == 456
