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

'''Qubes U2F Proxy daemon'''

import argparse
import asyncio
import functools
import logging
import signal

from .. import const
from .. import hidemu
from .. import proto
from .. import tools
from .. import uhid
from .. import util


class U2FHIDQrexecDevice(hidemu.U2FHIDDevice):
    '''U2DHIDDevice proxied over qrexec'''
    qrexec_client = const.QREXEC_CLIENT
    u2f_version = const.U2F_VERSION

    def __init__(self, vmname, *, name=None, **kwargs):
        if name is None:
            name = 'Qubes OS U2F proxy to {}'.format(vmname)
        super().__init__(name=name, **kwargs)
        self.vmname = vmname

    async def qrexec_transaction(self, capdu, rpcname):
        '''Execute one transaction over qrexec

        :param qubesu2f.proto.CommandAPDU capdu: command APDU
        :param str rpcname: name of the qrexec call
        '''

        self.log.getChild('qrexec').debug(
            'qrexec_transaction(capdu, rpcname=%r)', rpcname)
        # TODO timeout? not really needed, browser will time out itself
        qrexec_client = await asyncio.create_subprocess_exec(
            self.qrexec_client, self.vmname, rpcname,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await qrexec_client.communicate(bytes(capdu))

        if qrexec_client.returncode == 126:
            # qrexec was denied by policy; return CONDITIONS_NOT_SATISFIED and
            # let the browser time out
            self.log.getChild('qrexec').warning('qrexec call was denied: '
                'vmname %s rpcname %s returncode %d',
                self.vmname, rpcname, qrexec_client.returncode)
            raise proto.APDUConditionsNotSatisfiedError()

        if not stdout or qrexec_client.returncode != 0:
            self.log.getChild('qrexec').warning(
                'qrexec_client.returncode=%r', qrexec_client.returncode)
            self.log.getChild('qrexec').debug(
                'qrexec_client stdout=%r stderr=%r', stdout, stderr)
            raise proto.APDUExecutionError()

        rapdu = capdu.APDU_RESPONSE.from_buffer(stdout)
        return rapdu

    # pylint: disable=missing-docstring

    async def handle_u2f_register(self, apdu):
        self.log.getChild('u2f').debug('handle_u2f_register()')
        rapdu = await self.qrexec_transaction(apdu, rpcname='u2f.Register')
        try:
            rapdu.raise_for_sw()
        except proto.APDUError:
            pass
        else:
            self.log.getChild('qrexec').warning(
                'successfully registered; u2f.Authenticate+%s',
                rapdu.qrexec_arg)

        return rapdu

    async def handle_u2f_authenticate(self, apdu):
        self.log.getChild('u2f').debug('handle_u2f_authenticate()')
        return await self.qrexec_transaction(apdu,
            rpcname='u2f.Authenticate+{}'.format(apdu.qrexec_arg))

    async def handle_u2f_version(self, apdu):
        self.log.getChild('u2f').debug('handle_u2f_version()')
        return self.u2f_version.encode('ascii') + bytes(const.U2F_SW.NO_ERROR)


parser = argparse.ArgumentParser()
parser.add_argument('--verbose', '-v',
    dest='loglevel',
    action='append_const', const=-10,
    help='increase verbosity')
parser.add_argument('--quiet', '-q',
    dest='loglevel',
    action='append_const', const=+10,
    help='decrease verbosity')

parser_hid = parser.add_argument_group('HID lowlevel configuration')

parser_hid.add_argument('--hid-name', metavar='NAME',
    help='device name (max 128 bytes)')
parser_hid.add_argument('--hid-phys', metavar='PHYS',
    help='physical interface identifier (max 64 bytes)')
parser_hid.add_argument('--hid-serial', '--hid-uniq', metavar='SERIAL',
    type=bytes,
    help='serial number (max 64 bytes)')
parser_hid.add_argument('--hid-vendor', '--hid-vid', metavar='VENDOR-ID',
    type=functools.partial(int, base=16),
    help='vendor ID (uint16 hexadecimal)')
parser_hid.add_argument('--hid-product', '--hid-pid', metavar='PRODUCT-ID',
    type=functools.partial(int, base=16),
    help='product ID (uint16 hexadecimal)')
parser_hid.add_argument('--hid-version', metavar='VERSION',
    type=int,
    help='version (uint32)')
parser_hid.add_argument('--hid-bus', metavar='BUS',
    type=tools.enum_getter(uhid.BUS),
    help='bus (uint16 or constant name without BUS_)')
parser_hid.add_argument('--hid-country', metavar='COUNTRY',
    help='country (uint32)')
parser_hid.add_argument('--hid-rdesc', '--hid-rd', metavar='REPORT-DESCRIPTOR',
    type=bytes,
    help='careful with this')

parser.add_argument('vmname', metavar='VMNAME',
    help='the name of the vm')

parser.set_defaults(loglevel=[logging.WARNING])

async def _sighandler(loop, device):
    await device.close()
    loop.stop()

def sighandler(signame, loop, device):
    '''Handle SIGINT/SIGTERM'''
    print('caught {}, exiting'.format(signame))
    asyncio.ensure_future(_sighandler(loop, device), loop=loop)

def main(args=None):
    '''Main routine of the proxy daemon'''
    args = parser.parse_args(args)
    logging.basicConfig(
        format='%(asctime)s %(name)s %(message)s',
        level=sum(args.loglevel))
    loop = asyncio.get_event_loop()

    device = U2FHIDQrexecDevice(args.vmname,
        name=args.hid_name,
        phys=args.hid_phys,
        serial=args.hid_serial,
        vendor=args.hid_vendor,
        product=args.hid_product,
        version=args.hid_version,
        bus=args.hid_bus,
        country=args.hid_country,
        rdesc=args.hid_rdesc,
        loop=loop)

    loop.run_until_complete(device.open())
    loop.run_until_complete(util.systemd_notify())

    for signame in ('SIGINT', 'SIGTERM'):
        loop.add_signal_handler(getattr(signal, signame),
            sighandler, signame, loop, device)

    try:
        loop.run_forever()
    finally:
        loop.close()

if __name__ == '__main__':
    main()
