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

# pylint: disable=line-too-long
"""Protocol CTAP1 classes and structures.

.. seealso::
    https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#u2f-interoperability
        Interoperating with CTAP1/U2F authenticators (June 21, 2022)
"""
import enum
import io
import logging
from typing import Optional

from fido2.ctap1 import Ctap1, RegistrationData, SignatureData, APDU, ApduError

from qubesctap import const
from qubesctap import util


# pylint: enable=line-too-long


# pylint: disable=invalid-name,missing-class-docstring
@enum.unique
class U2F_AUTH(enum.IntEnum):
    CHECK_ONLY = 0x07
    ENFORCE = 0x03
    NO_ENFORCE = 0x08


class PrintableApduError(ApduError):
    def __str__(self) -> str:
        try:
            error_str = APDU(self.code).name
        except ValueError:
            error_str = f"{format(self.code, '#x')} {self.data.decode()}"
        return error_str


class CommandAPDUMeta(type):
    """Metaclass for :class:`CommandAPDU`"""
    _known_ins: dict = {}
    def __init__(cls, name, bases, dct):
        super().__init__(name, bases, dct)
        ins = dct['APDU_INS']
        assert ins not in cls._known_ins
        cls._known_ins[ins] = cls

    def get_class_for_ins(cls, untrusted_ins):
        """Given INS, return appropriate class"""
        # will raise KeyError if not already defined
        return cls._known_ins[untrusted_ins]

# CLA INS P1 P2 [0] [Lc1 Lc2 <request-data>] [Le1 Le2]
class CommandAPDU(metaclass=CommandAPDUMeta):
    """Abstract class for command (request) APDU"""
    # != to any int, so fails .verify_ins() unless overridden in subclass
    APDU_INS: Optional[Ctap1.INS] = None

    def __new__(cls, untrusted_cla, untrusted_ins, untrusted_p1,
            untrusted_p2, untrusted_request_data, untrusted_le):
        # pylint: disable=too-many-arguments,unused-argument
        if cls.APDU_INS is None:
            # pylint: disable=no-member,self-cls-assignment
            cls = cls.get_class_for_ins(untrusted_ins=untrusted_ins)
        return super().__new__(cls)

    def __init__(self, untrusted_cla, untrusted_ins, untrusted_p1,
            untrusted_p2, untrusted_request_data, untrusted_le):
        # pylint: disable=too-many-arguments

        self.log = logging.getLogger(type(self).__name__)
        self.log.debug('__init__(untrusted_cla=%r, untrusted_ins=%r, '
            'untrusted_p1=%r, untrusted_p2=%r, untrusted_request_data=%s, '
            'untrusted_le=%r)', untrusted_cla, untrusted_ins, untrusted_p1,
            untrusted_p2, util.hexlify(untrusted_data=untrusted_request_data),
            untrusted_le)

        try:
            self.cla = self.verify_cla(untrusted_cla=untrusted_cla)
            self.ins = self.verify_ins(untrusted_ins=untrusted_ins)
            self.p1 = self.verify_p1(untrusted_p1=untrusted_p1)
            self.p2 = self.verify_p2(untrusted_p2=untrusted_p2)
            self.le = self.verify_le(untrusted_le=untrusted_le)

            self.request_data = self.verify_request_data(
                untrusted_request_data=untrusted_request_data)

        except ApduError:
            raise

        except Exception:
            # pylint: disable=raise-missing-from
            self.log.error('__init__ exception:', exc_info=True)
            raise ApduError(APDU.WRONG_DATA)

    def _assemble(self, write):
        write(bytes((self.cla,)))
        write(bytes((self.ins,)))
        write(bytes((self.p1,)))
        write(bytes((self.p2,)))

        if self.request_data or self.le:
            # HID always uses extended length APDU encoding [CTAPHID 2]
            write(b'\0')

        if self.request_data:
            write(util.u16n_write(len(self.request_data)))
            write(self.request_data, request_data=True)

        if self.le:
            # for 65536 this is 0x00 0x00
            write(util.u16n_write(self.le))

    def __bytes__(self):
        buf = io.BytesIO()
        def write(token, request_data=None):
            # pylint: disable=unused-argument,missing-docstring
            return buf.write(token)
        self._assemble(write)
        return buf.getvalue()

    def hexdump(self):
        """Return a hexdump of the packet"""
        tokens = []
        def write(token, request_data=None):
            # pylint: disable=missing-docstring
            tokens.append(util.hexlify(token) if not request_data
                else self.hexdump_request_data())
        self._assemble(write)
        return ' '.join(tokens)

    def hexdump_request_data(self):
        # pylint: disable=missing-docstring
        return util.hexlify(self.request_data)

    def verify_cla(self, *, untrusted_cla):
        """Verify CLA octet.

        This accepts only 0x00. Subclass may overload this method and provide
        appropriate implementation.
        """
        if untrusted_cla != 0x00:
            raise ApduError(APDU.WRONG_DATA)
        cla = untrusted_cla
        return cla

    def verify_ins(self, *, untrusted_ins):
        """Verify INS octet.

        This checks if the argument matches respective
        :const:`CommandAPDU.APDU_INS` value for the class.
        """
        untrusted_ins = Ctap1.INS(untrusted_ins)
        assert untrusted_ins == type(self).APDU_INS
        ins = untrusted_ins
        return ins

    # pylint: disable=unused-argument
    def verify_p1(self, *, untrusted_p1):
        """Verify P1 octet.

        This accepts only 0x00. Subclass may overload this method and provide
        appropriate implementation.
        """
        p1 = 0x00
        return p1

    def verify_p2(self, *, untrusted_p2):
        """Verify P2 octet.

        This accepts only 0x00. Subclass may overload this method and provide
        appropriate implementation.
        """
        assert untrusted_p2 == 0x00
        p2 = untrusted_p2
        return p2

    def verify_le(self, *, untrusted_le):
        """Verify Le value.

        This does nothing. Subclass may overload this method and provide
        appropriate implementation.
        """
        le = untrusted_le
        return le

    def verify_request_data(self, *, untrusted_request_data):
        """Verify request-data.

        Subclass should overload this method with appropriate implementation.
        """
        raise NotImplementedError()

    @classmethod
    def from_bytes(cls, untrusted_data):
        """Get a class' instance given :class:`bytes` object.

        :raises APDUError: upon validadion

        May be called from a particular subclass to ensure INS value.
        """
        log = logging.getLogger(cls.__name__)
        log.debug('from_buffer(untrusted_data=%s)',
            util.hexlify(untrusted_data=untrusted_data))
        try:
            (untrusted_cla, untrusted_ins, untrusted_p1, untrusted_p2,
                ) = untrusted_data[:4]
        except ValueError:
            # pylint: disable=raise-missing-from
            raise ApduError(APDU.WRONG_DATA, b'data truncated at header')

        if len(untrusted_data) == 4:
            untrusted_request_data = b''
            untrusted_le = 0

        elif not untrusted_data[4] == 0:
            raise ApduError(APDU.WRONG_DATA, b'expected extended length encoding')

        else:
            lc = util.u16n_read(untrusted_data, 5)

            untrusted_request_data = untrusted_data[7:7+lc]
            if len(untrusted_request_data) != lc:
                raise ApduError(APDU.WRONG_DATA, b'data truncated at request_data')

            log.debug('from_buffer lc=%s untrusted_request_data=%s',
                lc, util.hexlify(untrusted_data=untrusted_request_data))

            if len(untrusted_data) == lc + 7:
                untrusted_le = 0
            elif len(untrusted_data) == lc + 9:
                untrusted_le = (
                    (util.u16n_read(untrusted_data, 7 + lc) - 1) % 0x10000 + 1)
            else:
                raise ApduError(APDU.WRONG_DATA, b'trailing garbage')

        return cls(
            untrusted_cla=untrusted_cla,
            untrusted_ins=untrusted_ins,
            untrusted_p1=untrusted_p1,
            untrusted_p2=untrusted_p2,
            untrusted_request_data=untrusted_request_data,
            untrusted_le=untrusted_le)

    def execute(self, ctap):
        """Should be implemented in subclasses."""
        raise NotImplementedError()


class Register(CommandAPDU):
    """U2F_REGISTER"""
    # pylint: disable=too-few-public-methods
    APDU_INS = Ctap1.INS.REGISTER

    def verify_request_data(self, *, untrusted_request_data):
        assert len(untrusted_request_data
            ) == const.U2F_NONCE_SIZE + const.U2F_APPID_SIZE
        request_data = untrusted_request_data
        return request_data

    # this is unspecified, but at least chromium seems to include it
    def verify_p1(self, *, untrusted_p1):
        # this raises ValueError if untrusted_p1 is not one of the enum values
        p1 = U2F_AUTH(untrusted_p1)
        return p1

    def hexdump_request_data(self):
        return util.hexlify_with_parition(self.request_data,
            const.U2F_NONCE_SIZE)

    def execute(self, ctap: Ctap1) -> RegistrationData:
        response = ctap.send_apdu(
            ins=Ctap1.INS.REGISTER,
            p1=self.p1,
            data=self.request_data,
        )
        result = RegistrationData(response)
        return result


class Authenticate(CommandAPDU):
    """U2F_AUTHENTICATE"""
    APDU_INS = Ctap1.INS.AUTHENTICATE

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 1 is for key_handle length octet
        offset = const.U2F_NONCE_SIZE + const.U2F_APPID_SIZE + 1
        self.key_handle = self.request_data[offset:]

    def verify_p1(self, *, untrusted_p1):
        # this raises ValueError if untrusted_p1 is not one of the enum values
        p1 = U2F_AUTH(untrusted_p1)
        return p1

    def verify_request_data(self, *, untrusted_request_data):
        kh_offset = const.U2F_NONCE_SIZE + const.U2F_APPID_SIZE
        kh_len = untrusted_request_data[kh_offset]  # raises IndexError
        assert kh_len <= const.MAX_KH_SIZE
        assert len(untrusted_request_data) == kh_offset + 1 + kh_len
        request_data = untrusted_request_data
        return request_data

    @property
    def qrexec_arg(self) -> str:
        """A qrexec argument for key_handle of this APDU"""
        return util.qrexec_arg(self.key_handle)

    def hexdump_request_data(self):
        return util.hexlify_with_parition(self.request_data,
            const.U2F_NONCE_SIZE, const.U2F_APPID_SIZE, 1)

    def execute(self, ctap: Ctap1) -> SignatureData:
        response = ctap.send_apdu(
            ins=Ctap1.INS.AUTHENTICATE,
            p1=0x03,
            data=self.request_data,
        )
        result = SignatureData(response)
        return result


class Version(CommandAPDU):
    """U2F_VERSION"""

    APDU_INS = Ctap1.INS.VERSION

    def verify_request_data(self, *, untrusted_request_data):
        assert not untrusted_request_data
        return b''

    def execute(self, ctap):
        """Never used, version is fixed in `qctap_proxy`."""
