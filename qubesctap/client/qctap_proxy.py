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

"""Qubes CTAP Proxy daemon"""

import argparse
import asyncio
import enum
import functools
import itertools
import logging
import signal

from fido2.ctap1 import APDU, ApduError, RegistrationData, SignatureData
from fido2.ctap2 import AssertionResponse, AttestationResponse, Ctap2

from qubesctap.protocol import ApduResponseWrapper, CborResponseWrapper, \
    RequestWrapper
from qubesctap import const, ctap2
from qubesctap.client import hidemu, uhid
from qubesctap import util
from qubesctap.util import int_to_bytes


class CTAPHIDQrexecDevice(hidemu.CTAPHIDDevice):
    """U2DHIDDevice proxied over qrexec"""
    qrexec_client = const.QREXEC_CLIENT
    ctap_version = const.U2F_VERSION

    def __init__(self, vmname, *, name=None, **kwargs):
        if name is None:
            name = f'Qubes OS CTAP proxy to {vmname}'
        super().__init__(name=name, **kwargs)
        self.vmname = vmname

    async def qrexec_transaction(self, request: RequestWrapper, rpcname: str):
        """Execute one transaction over qrexec"""
        self.log.getChild('qrexec').debug(
            'qrexec_transaction(capdu, rpcname=%r)', rpcname)
        # timeout not really needed, browser will time out itself
        qrexec_client = await asyncio.create_subprocess_exec(
            self.qrexec_client, self.vmname, rpcname,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await qrexec_client.communicate(bytes(request))

        if qrexec_client.returncode == 126:
            # qrexec was denied by policy; return USE_NOT_SATISFIED and
            # let the browser time out
            self.log.getChild('qrexec').warning('qrexec call was denied: '
                'vmname %s rpcname %s returncode %d',
                self.vmname, rpcname, qrexec_client.returncode)
            raise ApduError(APDU.USE_NOT_SATISFIED)

        if not stdout or qrexec_client.returncode != 0:
            self.log.getChild('qrexec').warning(
                'qrexec_client.returncode=%r', qrexec_client.returncode)
            self.log.getChild('qrexec').debug(
                'qrexec_client stdout=%r stderr=%r', stdout, stderr)
            raise ApduError(APDU.USE_NOT_SATISFIED)

        return stdout

    # pylint: disable=missing-docstring

    async def handle_fido2_get_info(self, cbor):
        self.log.getChild('ctap').debug('handle_fido2_get_info()')
        response = await self.qrexec_transaction(
            cbor, rpcname='ctap.GetInfo')
        wrapped_resp = CborResponseWrapper.from_bytes(
            response, expected_type=ctap2.Info)
        if not await self._pin_allowed():
            self._modify_info(wrapped_resp)
        return wrapped_resp

    async def _pin_allowed(self):
        """
        Test if RPC `ctap.ClientPin` is allowed
        """
        try:
            # try to send some info
            _ = await self.qrexec_transaction(
                RequestWrapper.from_bytes(chr(Ctap2.CMD.GET_INFO).encode()),
                rpcname='ctap.ClientPin'
            )
        except ApduError as err:
            if err.code == APDU.USE_NOT_SATISFIED:
                self.log.getChild('ctap').info('ctap.ClientPin disabled')
                return False
            raise
        return True

    def _modify_info(self, wrapped_resp):
        """
        Remove the list of supported PIN protocols.

        This way, if the `ctap.ClientPin` RPC is disabled, the client will be
        aware of it and won't prompt for a PIN during authentication,
        which would otherwise result in a timeout.
        """
        # copy values of immutable Info object
        resp_dict = {key: wrapped_resp.data[key] for key in wrapped_resp.data}
        # do a job
        del resp_dict[0x06]
        # construct new immutable Info object
        _data = ctap2.Info.from_dict(resp_dict)
        # replace data in wrapper
        wrapped_resp.data = _data


    async def handle_fido2_client_pin(self, cbor):
        self.log.getChild('ctap').debug('handle_fido2_client_pin()')
        response = await self.qrexec_transaction(
            cbor, rpcname='ctap.ClientPin')
        return CborResponseWrapper.from_bytes(
            response, expected_type=ctap2.ClientPINResponse)

    async def handle_fido2_make_credential(self, cbor):
        self.log.getChild('ctap').debug('handle_fido2_make_credential()')
        response = await self.qrexec_transaction(
            cbor, rpcname='u2f.Register')
        return CborResponseWrapper.from_bytes(
            response, expected_type=AttestationResponse)

    async def handle_fido2_get_assertion(self, cbor):
        self.log.getChild('ctap').debug('handle_fido2_get_assertion()')
        self.log.getChild('ctap').debug('%s', str(list(cbor.qrexec_args)))
        for qrexec_arg in cbor.qrexec_args:
            # pylint: disable=broad-except
            try:
                response = await self.qrexec_transaction(
                    cbor, rpcname=f'u2f.Authenticate+{qrexec_arg}')
                return CborResponseWrapper.from_bytes(
                    response, expected_type=AssertionResponse)
            except Exception as err:
                self.log.getChild('ctap').error('%s', str(err))
        return CborResponseWrapper(None)


    async def handle_u2f_register(self, apdu):
        self.log.getChild('ctap').debug('handle_u2f_register()')
        untrusted_response = await self.qrexec_transaction(
            apdu, rpcname='u2f.Register')
        response = ApduResponseWrapper.from_bytes(
            untrusted_response, expected_type=RegistrationData)
        if response.is_ok:
            self.log.getChild('qrexec').warning(
                'successfully registered; u2f.Authenticate+%s',
                response.qrexec_arg)
        return response

    async def handle_u2f_authenticate(self, apdu):
        self.log.getChild('ctap').debug('handle_u2f_authenticate()')
        untrusted_response = await self.qrexec_transaction(
            apdu, rpcname=f'u2f.Authenticate+{tuple(apdu.qrexec_args)[0]}')
        response = ApduResponseWrapper.from_bytes(
            untrusted_response, expected_type=SignatureData)
        return response


    async def handle_u2f_version(self, apdu):
        self.log.getChild('ctap').debug('handle_u2f_version()')
        return self.ctap_version.encode('ascii') + int_to_bytes(APDU.OK)


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
    type=bytes,  # type: ignore
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


def enum_getter(enum_type):
    """For use as ``type=`` argument to :class:`argparse.ArgumentParser`"""

    enum_builtin_type = next(itertools.dropwhile(
        (lambda t: issubclass(t, enum.Enum)), enum_type.__mro__))

    if enum_builtin_type is object:
        # this is needed to solve ambiguity between 6 and '6'
        raise TypeError('need an uniform enum; mix a builtin type '
            'into your Enum class, or use IntEnum which does the same')

    def _getter(value):
        try:
            return enum_type(enum_builtin_type(value))
        except ValueError:
            return getattr(enum_type, value)

    return _getter


parser_hid.add_argument('--hid-bus', metavar='BUS',
                        type=enum_getter(uhid.BUS),
                        help='bus (uint16 or constant name without BUS_)')
parser_hid.add_argument('--hid-country', metavar='COUNTRY',
    help='country (uint32)')
parser_hid.add_argument('--hid-rdesc', '--hid-rd', metavar='REPORT-DESCRIPTOR',
    type=bytes,  # type: ignore
    help='careful with this')

parser.add_argument('vmname', metavar='VMNAME',
    help='the name of the vm')

parser.set_defaults(loglevel=[logging.WARNING])

async def _sighandler(loop, device):
    await device.close()
    loop.stop()

def sighandler(signame, loop, device):
    """Handle SIGINT/SIGTERM"""
    print(f'caught {signame}, exiting')
    asyncio.ensure_future(_sighandler(loop, device), loop=loop)

def main(args=None):
    """Main routine of the proxy daemon"""
    args = parser.parse_args(args)
    logging.basicConfig(
        format='%(asctime)s %(name)s %(message)s',
        filename='/var/log/qubes/qctap',
        level=sum(args.loglevel),
    )

    loop = asyncio.get_event_loop()

    device = CTAPHIDQrexecDevice(args.vmname,
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
