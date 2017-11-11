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

'''Pure Python API to UHID virtual device'''

import asyncio
import ctypes
import distutils.version
import enum
import errno
import logging

from . import util

# pylint: disable=invalid-name,missing-docstring,too-few-public-methods

#include <linux/input.h>
@enum.unique
class BUS(enum.IntEnum):
    PCI         = 0x01
    ISAPNP      = 0x02
    USB         = 0x03
    HIL         = 0x04
    BLUETOOTH   = 0x05
    VIRTUAL     = 0x06
    ISA         = 0x10
    I8042       = 0x11
    XTKBD       = 0x12
    RS232       = 0x13
    GAMEPORT    = 0x14
    PARPORT     = 0x15
    AMIGA       = 0x16
    ADB         = 0x17
    I2C         = 0x18
    HOST        = 0x19
    GSC         = 0x1A
    ATARI       = 0x1B
    SPI         = 0x1C
    RMI         = 0x1D
    CEC         = 0x1E
    INTEL_ISHTP = 0x1F

#include <linux/hid.h>
#include <linux/uhid.h>

HID_MAX_DESCRIPTOR_SIZE = 4096

UHID_DATA_MAX = 4096

@enum.unique
class UHID(enum.IntEnum):
    (
    LEGACY_CREATE,
    DESTROY,
    START,
    STOP,
    OPEN,
    CLOSE,
    OUTPUT,
    LEGACY_OUTPUT_EV,
    LEGACY_INPUT,
    GET_REPORT,
    GET_REPORT_REPLY,
    CREATE2,
    INPUT2,
    SET_REPORT,
    SET_REPORT_REPLY,
    ) = range(15)

@enum.unique
class UHID_DEV_FLAGS(enum.IntEnum):
    NUMBERED_FEATURE_REPORTS = (1 << 0)
    NUMBERED_OUTPUT_REPORTS  = (1 << 1)
    NUMBERED_INPUT_REPORTS   = (1 << 2)

@enum.unique
class UHID_REPORT(enum.IntEnum):
    (
    FEATURE,
    OUTPUT,
    INPUT,
    ) = range(3)


#struct uhid_create2_req {
#       __u8 name[128];
#       __u8 phys[64];
#       __u8 uniq[64];
#       __u16 rd_size;
#       __u16 bus;
#       __u32 vendor;
#       __u32 product;
#       __u32 version;
#       __u32 country;
#       __u8 rd_data[HID_MAX_DESCRIPTOR_SIZE];
#} __attribute__((__packed__));
class uhid_create2_req(ctypes.Structure):
    _pack_ = True
    _fields_ = (
        ('name', ctypes.c_char * 128),
        ('phys', ctypes.c_char * 64),
        ('uniq', ctypes.c_char * 64),
        ('rd_size', ctypes.c_uint16),
        ('bus', ctypes.c_uint16),
        ('vendor', ctypes.c_uint32),
        ('product', ctypes.c_uint32),
        ('version', ctypes.c_uint32),
        ('country', ctypes.c_uint32),
        ('rd_data', ctypes.c_uint8 * HID_MAX_DESCRIPTOR_SIZE),
    )

    rd = util.raw_data('rd_data', 'rd_size')

#struct uhid_start_req {
#       __u64 dev_flags;
#};
class uhid_start_req(ctypes.Structure):
    _fields_ = (
        ('dev_flags', ctypes.c_uint64),
    )


#struct uhid_input2_req {
#       __u16 size;
#       __u8 data[UHID_DATA_MAX];
#} __attribute__((__packed__));
class uhid_input2_req(ctypes.Structure):
    _pack_ = True
    _fields_ = (
        ('_size', ctypes.c_uint16),
        ('_data', ctypes.c_uint8 * UHID_DATA_MAX),
    )

    data = util.raw_data('_data', '_size')

#struct uhid_output_req {
#       __u8 data[UHID_DATA_MAX];
#       __u16 size;
#       __u8 rtype;
#} __attribute__((__packed__));
class uhid_output_req(ctypes.Structure):
    _pack_ = True
    _fields_ = (
        ('data', ctypes.c_uint8 * UHID_DATA_MAX),
        ('size', ctypes.c_uint16),
        ('rtype', ctypes.c_uint8),
    )

#   data = util.raw_data('_data', '_size')

#struct uhid_get_report_req {
#       __u32 id;
#       __u8 rnum;
#       __u8 rtype;
#} __attribute__((__packed__));
class uhid_get_report_req(ctypes.Structure):
    _pack_ = True
    _fields_ = (
        ('id', ctypes.c_uint32),
        ('rnum', ctypes.c_uint8),
        ('rtype', ctypes.c_uint8),
    )

#struct uhid_get_report_reply_req {
#       __u32 id;
#       __u16 err;
#       __u16 size;
#       __u8 data[UHID_DATA_MAX];
#} __attribute__((__packed__));
class uhid_get_report_reply_req(ctypes.Structure):
    _pack_ = True
    _fields_ = (
        ('id', ctypes.c_uint32),
        ('err', ctypes.c_uint16),
        ('_size', ctypes.c_uint16),
        ('_data', ctypes.c_uint8 * UHID_DATA_MAX),
    )

    data = util.raw_data('_data', '_size')

#struct uhid_set_report_req {
#       __u32 id;
#       __u8 rnum;
#       __u8 rtype;
#       __u16 size;
#       __u8 data[UHID_DATA_MAX];
#} __attribute__((__packed__));
class uhid_set_report_req(ctypes.Structure):
    _pack_ = True
    _fields_ = (
        ('id', ctypes.c_uint32),
        ('rnum', ctypes.c_uint8),
        ('rtype', ctypes.c_uint8),
        ('_size', ctypes.c_uint16),
        ('_data', ctypes.c_uint8 * UHID_DATA_MAX),
    )

    data = util.raw_data('_data', '_size')

#struct uhid_set_report_reply_req {
#       __u32 id;
#       __u16 err;
#} __attribute__((__packed__));
class uhid_set_report_reply_req(ctypes.Structure):
    _pack_ = True
    _fields_ = (
        ('id', ctypes.c_uint32),
        ('err', ctypes.c_uint16),
    )


#struct uhid_event {
#       __u32 type;
#
#       union {
#               struct uhid_create_req create;
#               struct uhid_input_req input;
#               struct uhid_output_req output;
#               struct uhid_output_ev_req output_ev;
#               struct uhid_feature_req feature;
#               struct uhid_get_report_req get_report;
#               struct uhid_feature_answer_req feature_answer;
#               struct uhid_get_report_reply_req get_report_reply;
#               struct uhid_create2_req create2;
#               struct uhid_input2_req input2;
#               struct uhid_set_report_req set_report;
#               struct uhid_set_report_reply_req set_report_reply;
#               struct uhid_start_req start;
#       } u;
#} __attribute__((__packed__));
class _uhid_event_union(ctypes.Union):
    _pack_ = True
    _fields_ = (
#       ('create', uhid_create_req),
#       ('input', uhid_input_req),
        ('output', uhid_output_req),
#       ('output_ev', uhid_output_ev_req),
#       ('feature', uhid_feature_req),
        ('get_report', uhid_get_report_req),
#       ('feature_answer', uhid_feature_answer_req),
        ('get_report_reply', uhid_get_report_reply_req),
        ('create2', uhid_create2_req),
        ('input2', uhid_input2_req),
        ('set_report', uhid_set_report_req),
        ('set_report_reply', uhid_set_report_reply_req),
        ('start', uhid_start_req),
    )


class uhid_event(ctypes.Structure):
    _pack_ = True
    _anonymous_ = ('u',)
    _fields_ = (
        ('type', ctypes.c_uint32),
        ('u', _uhid_event_union),
    )

    def __repr__(self):
        event_type = UHID(self.type)
        uattr = event_type.name.lower()

        try:
            union = getattr(self, uattr)
        except AttributeError:
            fields = []
        else:
            fields = list(field for field, _ in union._fields_)

            for attrname in dir(type(union)):
                try:
                    attr = getattr(type(union), attrname)
                except AttributeError:
                    continue
                if not isinstance(attr, util.raw_data):
                    continue

                fields[fields.index(attr.data)] = attrname
                if attr.size is not None and attr.size.startswith('_'):
                    fields.remove(attr.size)

        return '{}(type={!s}{})'.format(type(self).__name__, event_type,
            ''.join(', u.{}.{}={}'.format(uattr, field, getattr(union, field))
                for field in fields))

# pylint: enable=invalid-name,missing-docstring,too-few-public-methods

class UHIDDevice(object):
    '''An abstract emulated device.

    You should inherit from this class and override at least
    :py:meth:`handle_uhid_output`, :py:meth:`handle_uhid_get_report` and
    :py:meth:`handle_uhid_set_report`.
    '''
    # pylint: disable=too-many-instance-attributes

    name = ''
    serial = b'\0'
    vendor = 0xdead
    product = 0xbeef
    version = 0
    phys = b'\0'
    country = 0
    rdesc = b'\0'  # TODO craft some null descriptor

    # Hidapi's hidraw backend assumes the device is either on BUS_USB or
    # BUS_BLUETOOTH. If it is BUS_USB, some additional introspection on /sys is
    # performed, which obviously fails. So let's set it to BUS_BLUETOOTH.
    # See https://github.com/signal11/hidapi/blob/master/linux/hid.c and
    # https://github.com/prefiks/u2f4moz/blob/master/c_src/hidapi/hid-linux-hidraw.c
    # (function `get_device_string` in both cases).
    bus = BUS.BLUETOOTH

    def __init__(self, name=None, serial=None, vendor=None, product=None,
            version=None, bus=None, phys=None, country=None, rdesc=None, *,
            loop=None):
        # pylint: disable=too-many-arguments
        self.log = logging.getLogger(type(self).__name__)

        self.log.getChild('uhid').debug('__init__(name=%r, serial=%r, '
            'vendor=%r, product=%r, version=%r, bus=%r, phys=%r, country=%r, '
            'rdesc=%r)',
            name, serial, vendor, product, version, bus, phys, country, rdesc)

        if name is not None:
            self.name = name
        if serial is not None:
            self.serial = serial
        if vendor is not None:
            self.vendor = vendor
        if product is not None:
            self.product = product
        if version is not None:
            self.version = version
        if bus is not None:
            self.bus = bus
        if phys is not None:
            self.phys = phys
        if country is not None:
            self.country = country
        if rdesc is not None:
            self.rdesc = rdesc

        self._normalize_version()

        self.loop = loop or asyncio.get_event_loop()
        self.fd = None

        self.is_started = asyncio.Event()
        self.is_open = asyncio.Event()

        self.dev_flags = {}

    def _normalize_version(self):
        if isinstance(self.version, int):
            # nothing to do
            return

        version = distutils.version.StrictVersion(self.version)
        major, minor, subminor = version.version
        if version.prerelease is None:
            pre = 0xff
        else:
            tag, pre = version.prerelease
            if tag == 'b':
                pre += 0x80
        self.version = (major << 24) + (minor << 16) + (subminor << 8) + pre

    async def open(self):
        '''Send CREATE2 event.'''

        self.log.getChild('uhid').debug('open()')
        self.fd = open('/dev/uhid', 'r+b', buffering=0)
        await self.write_uhid_req(UHID.CREATE2,
            name=self.name.encode('utf-8'),
            phys=self.phys,
            uniq=self.serial,
            bus=self.bus,
            vendor=self.vendor,
            product=self.product,
            version=self.version,
            country=self.country,
            rd=self.rdesc)
        self.loop.add_reader(self.fd, self._read_req)

    async def close(self):
        '''Send DESTROY event.'''

        self.log.debug('close()')
        await self.write_uhid_req(UHID.DESTROY)
        self.loop.remove_reader(self.fd)
        self.fd.close()

    async def write_uhid_req(self, event, **kwargs):
        '''Send an event to uhid device

        :param event: either a structure or a value from :py:class:`UHID`.

        *kwargs* will all be :py:func:`setattr` on the structure.
        '''

        if not isinstance(event, uhid_event):
            event = uhid_event(type=event)

        event_type = UHID(event.type)
        self.log.getChild('uhid').debug(
            'write_uhid_req(event.type={!s}, *{})'.format(event_type,
                ''.join(', {}={}'.format(k, util.maybe_hexlify(v))
                    for k, v in kwargs.items())))

        try:
            union = getattr(event, event_type.name.lower())
        except AttributeError:
            # event without payload
            assert not kwargs

        for attr, value in kwargs.items():
            field = getattr(union, attr)
            if isinstance(field, ctypes.Array):
                ctypes.memmove(field, value, min(
                    ctypes.sizeof(field),
                    ctypes.sizeof(value)
                        if isinstance(value, ctypes.Array) else len(value)))
            else:
                setattr(union, attr, value)

        return await self.loop.run_in_executor(None, self.fd.write, event)

    def _read_req(self):
        # there is .read(), which is definitely an IO operation, but this is
        # called from loop's reader, so this shouldn't block
        buffer = self.fd.read(ctypes.sizeof(uhid_event))
        event = uhid_event.from_buffer_copy(buffer)
        self.log.getChild('uhid').debug('_read_req() -> %r', event)
        handler = getattr(self,
            'handle_hid_{}'.format(UHID(event.type).name.lower()))
        return handler(event)

    # pylint: disable=missing-docstring

    def handle_hid_start(self, event):
        self.log.getChild('uhid').debug(
            'handle_hid_start(event.start.dev_flags=%r)',
            event.start.dev_flags)
        for flag in UHID_DEV_FLAGS:
            self.dev_flags[flag] = bool(event.start.dev_flags & flag)
        self.is_started.set()

    def handle_hid_stop(self, event):
        # pylint: disable=unused-argument
        self.log.getChild('uhid').debug('handle_hid_stop()')
        self.is_started.clear()

    def handle_hid_open(self, event):
        # pylint: disable=unused-argument
        self.log.getChild('uhid').debug('handle_hid_open()')
        self.is_open.set()

    def handle_hid_close(self, event):
        # pylint: disable=unused-argument
        self.log.getChild('uhid').debug('handle_hid_close()')
        self.is_open.clear()

    def handle_hid_output(self, event):
        # pylint: disable=unused-argument
        self.log.getChild('uhid').debug('handle_hid_output()')
        self.log.getChild('uhid').warning('WARNING: unhandled OUTPUT event')

    def handle_hid_get_report(self, event):
        self.log.getChild('uhid').debug('handle_hid_get_report()')
        asyncio.ensure_future(self.write_uhid_req(
            UHID.GET_REPORT_REPLY, id=event.id, err=errno.EIO), loop=self.loop)

    def handle_hid_set_report(self, event):
        self.log.getChild('uhid').debug('handle_hid_set_report()')
        asyncio.ensure_future(self.write_uhid_req(
            UHID.SET_REPORT_REPLY, id=event.id, err=errno.EIO), loop=self.loop)
