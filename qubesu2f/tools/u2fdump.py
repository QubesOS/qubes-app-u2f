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

# pylint: skip-file

import argparse
import asyncio
import binascii
import ctypes
import datetime
import enum
import fcntl
import io
import signal
import struct

from .. import const

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

class USBMonPacket:
    def __init__(self, hdr, data):
#       self.hdr = hdr
#       self.data_raw = data

        for attr in ('busnum', 'devnum', 'length', 'len_cap'):
            setattr(self, attr, getattr(hdr, attr))

        self.timestamp = datetime.datetime.fromtimestamp(hdr.ts_sec,
                tz=datetime.timezone.utc).replace(microsecond=hdr.ts_usec)

        self.epnum = hdr.epnum & 0xf
        self.dir_in = bool(hdr.epnum & 0x80)

        self.data = data.raw[:hdr.len_cap]

    def __str__(self):
        return ('{:%S.%f%z} '
                '{}:{:03d}:{} {} {}{}{} {}').format(
            self.timestamp, self.busnum, self.devnum, self.epnum,
            ('I' if self.dir_in else 'O'), self.length,
            ('!' if len(self.data) != self.length else '/'),
            self.len_cap, binascii.hexlify(self.data).decode('ascii'))


class USBMon:
    packet_class = USBMonPacket

    def __init__(self, fd, bufsize=const.HID_FRAME_SIZE):
        self.fd = fd
        self.bufsize = bufsize

    def __aiter__(self):
        return self

    async def __anext__(self):
        hdr = _USBMonPacket()
        data = ctypes.create_string_buffer(self.bufsize)

        arg = _USBMonGetArg()
        arg.hdr = ctypes.pointer(hdr)
        arg.data = ctypes.cast(data, ctypes.c_void_p)
        arg.alloc = ctypes.sizeof(data)

        await asyncio.get_event_loop().run_in_executor(None,
            fcntl.ioctl, self.fd, const.MON_IOCX_GETX, arg)

        return self.packet_class(hdr, data)

class USBMonU2FHIDPacket(USBMonPacket):
    s_u2fhid_head = struct.Struct('>IB')
    s_u2fhid_bcnt = struct.Struct('>H')
    s_apdu_hdr = struct.Struct('>BBBB')

    _attrs = (
        ('cid', '{:08x}'),
        ('cmd', '{!s}'),
        ('seq', '{:02x}'),
        ('bcnt', '{:d}'),
        ('cla', '{:02x}'),
        ('ins', '{!s}'),
        ('p1', '{:02x}'),
        ('p2', '{:02x}'),
        ('apdu_is_complete', '{}'),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if len(self.data) != const.HID_FRAME_SIZE:
            return

        self.cid, cmd_or_seq = self.s_u2fhid_head.unpack_from(self.data)
        self.is_init = bool(cmd_or_seq & TYPE_INIT)

        if self.is_init:
            self.cmd = const.U2FHID(cmd_or_seq)
            self.seq = None
            (self.bcnt,) = self.s_u2fhid_bcnt.unpack_from(self.data, 5)
            self.apdu_is_complete = self.bcnt > const.HID_FRAME_SIZE - 7

            if self.cmd == const.U2FHID.MSG and not self.dir_in:
                (self.cla, self.ins, self.p1, self.p2
                    ) = self.s_apdu_hdr.unpack_from(self.data, 7)
                try:
                    self.ins = const.U2F(self.ins)
                except ValueError:
                    self.ins = 'UNKNOWN({:02x})'.format(self.ins)
            else:
                self.cla = self.ins = self.p1 = self.p2 = None

        else:
            self.cmd = None
            self.seq = cmd_or_seq
            self.bcnt = None
            self.apdu_is_complete = False
            self.cla = self.ins = self.p1 = self.p2 = None

    def __str__(self):
        if len(self.data) != const.HID_FRAME_SIZE:
            return super().__str__()

        attrs = ((attr, fmt, getattr(self, attr)) for attr, fmt in self._attrs)
        attrs = ('{} {}'.format(attr, fmt.format(value))
            for attr, fmt, value in attrs if value is not None)

        return '{}\n  {}'.format(super().__str__(), ' '.join(attrs))

class U2FMon(USBMon):
    packet_class = USBMonU2FHIDPacket

async def u2fmon(bus=0, device=-1):
    try:
        with open(USBMONPATH.format(bus=bus), 'rb', buffering=0) as fd:
            async for packet in U2FMon(fd):
                if device >= 0 and packet.devnum != device:
                    continue
                print(packet)
    except asyncio.CancelledError:
        return


def sighandler(signame, fut):
    print('caught {}, exiting'.format(signame))
    fut.cancel()

parser = argparse.ArgumentParser()
parser.add_argument('--bus', '-b',
    type=int,
    help='USB bus number (0 for all) (default: %d)')
parser.add_argument('--device', '-d',
    type=int,
    help='USB device number (<0 for all) (default: %d)')
parser.set_defaults(bus=0, device=-1)

def main(args=None):
    args = parser.parse_args(args)
    loop = asyncio.get_event_loop()

    fut = loop.create_task(u2fmon(args.bus, args.device))
    for signame in ('SIGINT', 'SIGTERM'):
        loop.add_signal_handler(getattr(signal, signame),
            sighandler, signame, fut)

    try:
        loop.run_until_complete(fut)
    finally:
        loop.close()

if __name__ == '__main__':
    main()
