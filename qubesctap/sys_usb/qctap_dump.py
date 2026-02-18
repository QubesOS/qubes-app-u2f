#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2017  Wojtek Porczyk <woju@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

"""Tracer for CTAPHID protocol with actual USB device.

This relies on usbmon packet capture, so it is not good for uhid emulation.
"""

# well, we're working with structs, so
# pylint: disable=too-few-public-methods,too-many-instance-attributes

import argparse
import asyncio
import ctypes
import datetime
import fcntl
import signal
import sys
from types import FrameType
from typing import Optional, Callable

import qubesctap.client.hid_data
from qubesctap import const
from qubesctap import util

# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/usb/usbmon.txt

# unfortunately text usbmon interface has data length capped at 32 bytes,
# so we have to use binary interface

USBMONPATH = '/dev/usbmon{bus}'

#struct usbmon_packet {
#       u64 id;                 /*  0: URB ID - from submission to callback */
#       unsigned char type;     /*  8: Same as text; extensible. */
#       unsigned char xfer_type; /*    ISO (0), Intr, Control, Bulk (3) */
#       unsigned char epnum;    /*     Endpoint number and transfer direction */
#       unsigned char devnum;   /*     Device address */
#       u16 busnum;             /* 12: Bus number */
#       char flag_setup;        /* 14: Same as text */
#       char flag_data;         /* 15: Same as text; Binary zero is OK. */
#       s64 ts_sec;             /* 16: gettimeofday */
#       s32 ts_usec;            /* 24: gettimeofday */
#       int status;             /* 28: */
#       unsigned int length;    /* 32: Length of data (submitted or actual) */
#       unsigned int len_cap;   /* 36: Delivered length */
#       union {                 /* 40: */
#               unsigned char setup[SETUP_LEN]; /* Only for Control S-type */
#               struct iso_rec {                /* Only for ISO */
#                       int error_count;
#                       int numdesc;
#               } iso;
#       } s;
#       int interval;           /* 48: Only for Interrupt and ISO */
#       int start_frame;        /* 52: For ISO */
#       unsigned int xfer_flags; /* 56: copy of URB's transfer_flags */
#       unsigned int ndesc;     /* 60: Actual number of ISO descriptors */
#};                             /* 64 total length */
class _USBMonPacketIsoRec(ctypes.Structure):
    _fields_ = (
        ('error_count', ctypes.c_int),
        ('numdesc', ctypes.c_int),
    )
class _USBMonPacketUnion(ctypes.Union):
    _fields_ = (
        ('setup', ctypes.c_ubyte * 8),
        ('iso', _USBMonPacketIsoRec),
    )
class _USBMonPacket(ctypes.Structure):
    _fields_ = (
        ('id', ctypes.c_uint64),
        ('type', ctypes.c_uint8),
        ('xfer_type', ctypes.c_uint8),
        ('epnum', ctypes.c_uint8),
        ('devnum', ctypes.c_uint8),
        ('busnum', ctypes.c_uint16),
        ('flag_setup', ctypes.c_char),
        ('flag_data', ctypes.c_char),
        ('ts_sec', ctypes.c_int64),
        ('ts_usec', ctypes.c_int32),
        ('status', ctypes.c_int),
        ('length', ctypes.c_uint),
        ('len_cap', ctypes.c_uint),
        ('s', _USBMonPacketUnion),
        ('interval', ctypes.c_int),
        ('start_frame', ctypes.c_int),
        ('xfer_flags', ctypes.c_uint),
        ('ndesc', ctypes.c_uint),
    )

#struct mon_get_arg {
#	struct usbmon_packet *hdr;
#	void *data;
#	size_t alloc;		/* Length of data (can be zero) */
#};
class _USBMonGetArg(ctypes.Structure):
    _fields_ = (
        ('hdr', ctypes.POINTER(_USBMonPacket)),
        ('data', ctypes.c_void_p),
        ('alloc', ctypes.c_size_t),
    )

# /usr/include/asm-generic/ioctl.h
#_IOC_NONE = 0
_IOC_WRITE = 1
#_IOC_READ = 2

def _IOC(dir, type, nr, size):
    # pylint: disable=invalid-name,redefined-builtin
    return (dir << 30) | (type << 8) | (nr << 0) | (size << 16)

def _IOW(type, nr, size):
    # pylint: disable=invalid-name,redefined-builtin
    return _IOC(_IOC_WRITE, type, nr, size)

MON_IOC_MAGIC = 0x92
MON_IOCX_GETX = _IOW(MON_IOC_MAGIC, 10, ctypes.sizeof(_USBMonGetArg))


class USBMonPacket:
    """A packet yielded from the monitor."""
    def __init__(self, hdr, data):
        self.busnum = hdr.busnum
        self.devnum = hdr.devnum
        self.length = hdr.length
        self.len_cap = hdr.len_cap

        self.timestamp = datetime.datetime.fromtimestamp(hdr.ts_sec,
                tz=datetime.timezone.utc).replace(microsecond=hdr.ts_usec)

        self.epnum = hdr.epnum & 0xf
        self.dir_in = bool(hdr.epnum & 0x80)

        if self.length == self.len_cap == const.HID_FRAME_SIZE:
            self.data = qubesctap.client.hid_data.CTAPHIDPacket.from_buffer(data)
        else:
            self.data = data.raw[:self.len_cap]

    def __str__(self):
        try:
            payload = self.data.hexdump()
        except AttributeError:
            payload = util.hexlify(self.data)

        return (f'{self.timestamp:%S.%f} '
                f'{self.busnum}:{self.devnum:03d}:{self.epnum} '
                f'{("I" if self.dir_in else "O")} {payload}')

class USBMon:
    """Async iterator yielding packets as they are received."""
    packet_class = USBMonPacket

    def __init__(self, fd, bufsize=const.HID_FRAME_SIZE):
        self.fd = fd
        self.bufsize = bufsize

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._queue: Optional[asyncio.Queue] = asyncio.Queue(32)
        self._closed = False

    async def start(self) -> "USBMon":
        """Attach the FD reader to the currently running loop."""
        if self._closed:
            raise RuntimeError("USBMon is closed")
        if self._loop is not None:
            return self  # already started

        self._loop = asyncio.get_running_loop()
        self._loop.add_reader(self.fd, self._reader)
        return self

    async def aclose(self) -> None:
        """Detach the FD reader and stop iteration."""
        if self._closed:
            return
        self._closed = True

        if self._loop is not None:
            self._loop.remove_reader(self.fd)
            self._loop = None

        # Drain queue to allow GC and ensure __anext__ stops quickly
        if self._queue is not None:
            while True:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except asyncio.QueueEmpty:
                    break
            self._queue = None

    async def __aenter__(self) -> "USBMon":
        return await self.start()

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._queue is None:
            raise StopAsyncIteration()

        try:
            packet = await self._queue.get()
            self._queue.task_done()
            return packet
        except asyncio.CancelledError as exc:
            # If the consumer is cancelled, detach
            await self.aclose()
            raise StopAsyncIteration from exc

    def _reader(self):
        hdr = _USBMonPacket()
        data = ctypes.create_string_buffer(self.bufsize)

        arg = _USBMonGetArg()
        arg.hdr = ctypes.pointer(hdr)  # pylint: disable=attribute-defined-outside-init
        arg.data = ctypes.cast(data, ctypes.c_void_p)  # pylint: disable=attribute-defined-outside-init
        arg.alloc = ctypes.sizeof(data)  # pylint: disable=attribute-defined-outside-init

        fcntl.ioctl(self.fd, MON_IOCX_GETX, arg)

        try:
            if self._queue is None:
                return
            self._queue.put_nowait(self.packet_class(hdr, data))
        except asyncio.QueueFull:
            sys.stderr.write('warning: queue full, dropping packet\n')

async def ctap_monitor(bus=0, device=-1):
    """Print one CTAPHID packet per line."""
    with open(USBMONPATH.format(bus=bus), 'rb', buffering=0) as fd:
        async with USBMon(fd) as mon:
            async for packet in mon:
                if 0 <= device != packet.devnum:
                    continue
                if not packet.length == packet.len_cap == const.HID_FRAME_SIZE:
                    continue
                print(packet)


parser = argparse.ArgumentParser()
parser.add_argument('--bus', '-b', type=int,
    help='USB bus number (0 for all) (default: %(default)d)')
parser.add_argument('--device', '-d', type=int,
    help='USB device number (<0 for all) (default: %(default)d)')
parser.set_defaults(bus=0, device=-1)

def _make_signal_handler(on_signal: Callable[[str], None], signame: str):
    def _handler(_signum: int, _frame: Optional[FrameType]) -> None:
        on_signal(signame)
    return _handler

async def main_async(args=None):
    """Main async function."""
    args = parser.parse_args(args)

    task = asyncio.create_task(ctap_monitor(args.bus, args.device))

    def on_signal(signame: str):
        print(f'caught {signame}, exiting')
        task.cancel()

    loop = asyncio.get_running_loop()
    for signame in ('SIGINT', 'SIGTERM'):
        try:
            loop.add_signal_handler(getattr(signal, signame), on_signal, signame)
        except NotImplementedError:
            signal.signal(getattr(signal, signame), _make_signal_handler(on_signal, signame))

    try:
        await task
    except asyncio.CancelledError:
        # expected on shutdown
        pass

def main(args=None):
    """Main function."""
    asyncio.run(main_async(args))

if __name__ == '__main__':
    main()
