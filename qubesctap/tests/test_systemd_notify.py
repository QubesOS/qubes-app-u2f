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
import socket

import pytest

from qubesctap import util


async def _recv_one(sock: socket.socket) -> bytes:
    """Receive one datagram without blocking the event loop."""
    # recvfrom() on AF_UNIX datagram blocks, so run it in a thread.
    return await asyncio.to_thread(lambda: sock.recv(4096))


@pytest.mark.asyncio
async def test_systemd_notify_sends_default_ready(monkeypatch, tmp_path):
    recv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    path = str(tmp_path / "notify.sock")
    recv_sock.bind(path)

    try:
        monkeypatch.setenv("NOTIFY_SOCKET", path)

        await util.systemd_notify()

        msg = await asyncio.wait_for(_recv_one(recv_sock), timeout=1.0)
        assert msg == b"READY=1"
    finally:
        recv_sock.close()


@pytest.mark.asyncio
async def test_systemd_notify_sends_kwargs(monkeypatch, tmp_path):
    recv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    path = str(tmp_path / "notify.sock")
    recv_sock.bind(path)

    try:
        monkeypatch.setenv("NOTIFY_SOCKET", path)

        await util.systemd_notify(status="started", ready=1)

        # util.systemd_notify() sends one datagram per kwarg, in dict order. :contentReference[oaicite:1]{index=1}
        msg1 = await asyncio.wait_for(_recv_one(recv_sock), timeout=1.0)
        msg2 = await asyncio.wait_for(_recv_one(recv_sock), timeout=1.0)

        assert msg1 == b"STATUS=started"
        assert msg2 == b"READY=1"
    finally:
        recv_sock.close()


@pytest.mark.asyncio
async def test_systemd_notify_without_notify_socket_does_nothing(monkeypatch):
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)

    # Should simply return without raising.
    await util.systemd_notify(status="ignored")


@pytest.mark.asyncio
async def test_systemd_notify_abstract_namespace_socket(monkeypatch):
    recv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    addr = "\0qubes-notify"  # abstract namespace bind

    try:
        recv_sock.bind(addr)
        monkeypatch.setenv("NOTIFY_SOCKET", "@qubes-notify")

        await util.systemd_notify(ready=1)

        msg = await asyncio.wait_for(_recv_one(recv_sock), timeout=1.0)
        assert msg == b"READY=1"
    finally:
        recv_sock.close()


@pytest.mark.asyncio
async def test_systemd_notify_create_endpoint_keyerror_returns(monkeypatch):
    """
    This hits the `except KeyError: return` path in systemd_notify(). :contentReference[oaicite:2]{index=2}
    We mock the loop method only for this one narrow branch.
    """
    monkeypatch.setenv("NOTIFY_SOCKET", "/tmp/qubes-notify.sock")

    loop = asyncio.get_running_loop()

    async def boom(*args, **kwargs):
        raise KeyError("simulate loop env/systemd issue")

    # Patch the class method (more reliable than instance patching across versions)
    monkeypatch.setattr(loop.__class__, "create_datagram_endpoint", boom)

    # Should not raise
    await util.systemd_notify(status="started")
