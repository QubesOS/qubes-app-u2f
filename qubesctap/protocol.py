# coding=utf-8
#
# The Qubes OS Project, http://www.qubes-os.org
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

"""
Wrappers for fido2 and our own implementation of classes of ctap commands.
"""

import logging
import pathlib
import re
import struct
from abc import ABC
from typing import Mapping, Optional, Union, Any, Iterable, Type

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap1 import Ctap1, RegistrationData, SignatureData, APDU, ApduError
from fido2.ctap2 import Ctap2, AssertionResponse, AttestationResponse

from qubesctap import ctap1, ctap2
from qubesctap.util import qrexec_arg, int_to_bytes

CTAP1_ACCEPTABLE_RESPONSES = (RegistrationData, SignatureData)
CTAP2_ACCEPTABLE_RESPONSES = (AssertionResponse, AttestationResponse,
                              ctap2.Info, ctap2.ClientPINResponse)


class InvalidRequest:
    """
    A class representing an invalid request.

    Attributes:
    - return_code: bytes
        the error code returned by the invalid request
    """
    def __init__(
            self, return_code: Union[bytes, int, APDU, CtapError] = b'\x01'):
        if isinstance(return_code, APDU):
            return_code = return_code.value
        if isinstance(return_code, CtapError):
            return_code = return_code.code
        if isinstance(return_code, int):
            return_code = bytes.fromhex(hex(return_code)[2:])
        self.return_code: bytes = return_code

    def execute(self, _: Any) -> bytes:
        """
        Returns the error code for the invalid request.
        """
        logging.getLogger('ctap').debug(
            "InvalidRequest.execute -> %s", self.return_code)
        return self.return_code

    def __bytes__(self):
        """
        Returns the error code for the invalid request.
        """
        return self.execute(None)


# pylint: disable=missing-class-docstring
class InvalidCommandError(Exception):
    pass


class CommunicatWrapper:
    """
    An abstract base class for CTAP1/CTAP2 communication wrappers.
    """
    def __bytes__(self):
        """
        Returns wrapped object as bytes.
        """
        return self.to_bytes()

    def to_bytes(self) -> bytes:
        """
        Converts wrapped object to bytes.
        """
        raise NotImplementedError()

    @staticmethod
    def from_bytes(
            untrusted_data: bytes, expected_type: Optional[type] = None
    ) -> "CommunicatWrapper":
        """
        Returns an instance of the wrapped class from bytes.
        """
        raise NotImplementedError()


class ResponseWrapper(CommunicatWrapper, ABC):
    """
    An abstract base class for CTAP1/CTAP2 response wrappers.
    """
    def __init__(self, data):
        self.data = data

    @property
    def qrexec_arg(self) -> str:
        """
        Returns the credential id hash as qrexec argument.
        """
        raise NotImplementedError()

    @property
    def is_ok(self) -> bool:
        """
        Returns True if wrapped response is not an error, False otherwise.
        """
        raise NotImplementedError()


class RequestWrapper(CommunicatWrapper, ABC):
    """
    An abstract base class for CTAP1/CTAP2 request wrappers.
    """
    def __init__(self, data):
        self.data = data

    @staticmethod
    def from_bytes(
            untrusted_data: bytes, expected_type: Optional[type] = None
    ) -> "RequestWrapper":
        """
        Returns wrapped instance of the CTAP1/CTAP2 request from bytes.
        """
        log = logging.getLogger('ctap.request')

        disable_protocols = set()
        if any(pathlib.Path(path).exists() for path in CTAP1_DISABLE_PATHS):
            log.warning("CTAP1 protocol is disabled. To enable this protocol "
                        "remove following files: %s",
                        ", ".join(CTAP1_DISABLE_PATHS))
            disable_protocols.add(1)
        elif any(pathlib.Path(path).exists() for path in CTAP2_DISABLE_PATHS):
            disable_protocols.add(2)
            log.warning("CTAP2 protocol is disabled. To enable this protocol "
                        "remove following files: %s",
                        ", ".join(CTAP2_DISABLE_PATHS))

        req_type, _ = untrusted_data[0], untrusted_data[1:]
        if req_type == 0 and 1 not in disable_protocols:
            req_cls: Type[RequestWrapper] = ApduRequestWrapper
            parser = ctap1.CommandAPDU.from_bytes
            log.info("APDU request: use CTAP 1 protocol.")
        elif 2 not in disable_protocols:
            req_cls = CborRequestWrapper
            parser = ctap2.Ctap2Request.from_bytes
            log.info("Use CTAP 2 protocol.")
        else:
            return CborRequestWrapper(InvalidRequest(APDU.USE_NOT_SATISFIED))

        # pylint: disable=broad-except
        try:
            request = parser(untrusted_data)
            result = req_cls(request)
            log.debug("return %s", req_cls.__name__)
            return result
        except ApduError as err:
            log.error("APDU parsing error: %s", str(err))
        except Exception as err:
            log.error("Parsing error: %s", str(err))

        request = InvalidRequest(APDU.WRONG_DATA)
        log.warning("return InvalidRequest(%s)", request.return_code)
        return CborRequestWrapper(request)

    def raise_error(self, protocol: Optional[str] = None):
        """
        If wrapped request is invalid raise an CTAP1/CTAP2 error.
        """
        if isinstance(self.data, InvalidRequest):
            code = int.from_bytes(self.data.return_code, "big")
            if protocol == "fido2":
                err: Union[CtapError, ApduError] = CtapError(code)
            elif protocol == "u2f":
                err = ApduError(code)
            else:
                try:
                    err = CtapError(code)
                except ValueError:
                    err = ApduError(code)
            raise err

    def execute(self, device) -> ResponseWrapper:
        """
        Execute wrapped request and return wrapped response.
        """
        raise NotImplementedError()

    @property
    def qrexec_args(self) -> Iterable[str]:
        """
        Returns iterable of credential id hashes as qrexec arguments.
        """
        raise NotImplementedError()

    def trim_allow_list(self, arg):
        """
        Remove credentials with different hash than the `arg`.
        """
        raise NotImplementedError()

    @property
    def name(self) -> str:
        """
        Return snake_case name of request.
        """
        raise NotImplementedError()


class ApduResponseWrapper(ResponseWrapper, ABC):
    """
    CTAP1 response wrapper.
    """
    def to_bytes(self) -> bytes:
        """
        Converts wrapped CTAP1 response to bytes and adds response code
        at the end.
        """
        if self.is_ok:
            return bytes(self.data) + b'\x90\x00'
        if isinstance(self.data, bytes):
            if len(self.data) == 2:
                return self.data
            return int_to_bytes(APDU.USE_NOT_SATISFIED)
        codes = {APDU.USE_NOT_SATISFIED: b'\x69\x85',
                 APDU.WRONG_DATA: b'\x6A\x80'}
        result = codes.get(self.data.code,
                         codes[APDU.USE_NOT_SATISFIED])
        return result

    @property
    def qrexec_arg(self) -> str:
        """
        Returns the credential id hash as qrexec argument.

        raises InvalidCommandError
        """
        if isinstance(self.data, RegistrationData):
            return qrexec_arg(self.data.key_handle)
        raise InvalidCommandError()

    @staticmethod
    def from_bytes(
            untrusted_data: bytes, expected_type: Optional[type] = None
    ) -> "ApduResponseWrapper":
        """
        Returns wrapped instance of the CTAP1 response from bytes.

        If `expected_type` is not given return wrapped `CtapError`.
        """
        logging.debug('ApduResponseWrapper.from_buffer(untrusted_data=%r)',
                      untrusted_data)
        status = struct.unpack(">H", untrusted_data[-2:])[0]
        data = untrusted_data[:-2]
        if status != APDU.OK:
            error = ctap1.PrintableApduError(status, data)
            logging.getLogger('ctap').warning("APDU error: %s", str(error))
            return ApduResponseWrapper(error)
        # pylint: disable=broad-except
        try:
            if expected_type == RegistrationData:
                return ApduResponseWrapper(RegistrationData(data))
            if expected_type == SignatureData:
                return ApduResponseWrapper(SignatureData(data))
        except Exception as err:
            logging.getLogger('ctap').error("%s", str(err))
        return ApduResponseWrapper(ApduError(APDU.USE_NOT_SATISFIED))

    @property
    def is_ok(self) -> bool:
        """
        Returns True if wrapped response is not an error, False otherwise.
        """
        return isinstance(self.data, CTAP1_ACCEPTABLE_RESPONSES)


class ApduRequestWrapper(RequestWrapper):
    @property
    def qrexec_args(self) -> Iterable[str]:
        """
        Returns iterable of credential id hashes as qrexec arguments.
        """
        if not isinstance(self.data, ctap1.Authenticate):
            raise InvalidCommandError()
        return [qrexec_arg(self.data.key_handle)]

    def trim_allow_list(self, arg):
        """ctap1.Authenticate can transport only one argument"""

    def execute(self, device) -> ApduResponseWrapper:
        """
        Execute wrapped CTAP1 request and return wrapped CTAP1 response.
        """
        # pylint: disable=broad-except
        try:
            response = self.data.execute(Ctap1(device))
        except ApduError as aerr:
            response = aerr
        except Exception as err:
            response = ApduError(APDU.USE_NOT_SATISFIED, str(err).encode())
        return ApduResponseWrapper(response)

    def to_bytes(self) -> bytes:
        """
        Converts wrapped CTAP2 requesrt to bytes.
        """
        return bytes(self.data)

    @property
    def name(self) -> str:
        """
        Return snake_case name of request.
        """
        return self.data.ins.name.lower()



class CborResponseWrapper(ResponseWrapper):
    """
    CTAP2 response wrapper.
    """
    def __init__(self, data, raw_ok: Optional[bytes] = None):
        super().__init__(data)
        self._raw_ok = raw_ok  # original CBOR bytes (without the status byte)

    def to_bytes(self) -> bytes:
        """
        Converts wrapped CTAP2 response to bytes and adds response code
        at the beginning.
        """
        if self.is_ok:
            if self._raw_ok is not None:
                return b'\x00' + self._raw_ok
            return b'\x00' + cbor.encode(self.data)

        if isinstance(self.data, CtapError):
            return int_to_bytes(self.data.code)

        return b'\x01'

    @property
    def qrexec_arg(self) -> str:
        """
        Returns the credential id hash as qrexec argument.
        """
        if isinstance(self.data, AttestationResponse):
            return qrexec_arg(
                self.data.auth_data.credential_data.credential_id # type: ignore
            )
        raise InvalidCommandError()
    
    @staticmethod
    def from_bytes(untrusted_data: bytes, expected_type=None) -> "CborResponseWrapper":
        status, enc = untrusted_data[0], untrusted_data[1:]
        if status != 0x00:
            return CborResponseWrapper(CtapError(status))

        # pylint: disable=broad-except
        try:
            decoded = cbor.decode(enc)
            if isinstance(decoded, Mapping) and expected_type is not None and hasattr(expected_type, "from_dict"):
                obj = expected_type.from_dict(decoded)
                return CborResponseWrapper(obj, raw_ok=enc)
        except Exception as err:
            logging.getLogger('ctap').error("%s", str(err))

        return CborResponseWrapper(CtapError(CtapError.ERR.INVALID_COMMAND))

    @property
    def is_ok(self) -> bool:
        """
        Returns True if wrapped response is not an error, False otherwise.
        """
        return isinstance(self.data, CTAP2_ACCEPTABLE_RESPONSES)

class CborRequestWrapper(RequestWrapper):
    @property
    def qrexec_args(self) -> Iterable[str]:
        """
        Returns iterable of credential id hashes as qrexec arguments.
        """
        if not isinstance(self.data, ctap2.GetAssertion):
            raise InvalidCommandError()
        if self.data.allow_list is None:
            return
        for cred in self.data.allow_list:
            yield qrexec_arg(cred['id'])

    def trim_allow_list(self, arg):
        """
        Remove credentials with different hash than the `arg`.
        """
        if not isinstance(self.data, ctap2.GetAssertion):
            raise InvalidCommandError()
        if self.data.allow_list is None:
            return
        allow_list = [cred for cred in self.data.allow_list
                      if qrexec_arg(cred['id']) == arg]
        trimmed_data_dict = {k: v for k, v in self.data.__dict__.items()
                             if not k.startswith("_")}
        trimmed_data_dict["allow_list"] = allow_list
        self.data = ctap2.GetAssertion(**trimmed_data_dict)

    def execute(self, device) -> ResponseWrapper:
        """
        Execute wrapped CTAP2 request and return wrapped CTAP2 response.
        """
        try:
            ctap: Union[Ctap1, Ctap2] = \
                Ctap2(device)  #fails if device do not support CTAP2
            logging.getLogger('ctap').debug("Execute CTAP2 request")
        except (ValueError, CtapError):
            logging.getLogger('ctap').warning(
                "Device do not support CTAP2, trying execute CTAP1 request")
            return ApduResponseWrapper(ApduError(APDU.WRONG_DATA))
        # pylint: disable=broad-except
        try:
            response = self.data.execute(ctap)
        except CtapError as err:
            response = err
        except Exception as err:
            logging.getLogger('ctap').error(
                "Unexpected response error: %s", err)
            response = CtapError(1)

        return CborResponseWrapper(response)

    def to_bytes(self) -> bytes:
        """
        Converts wrapped CTAP2 requesrt to bytes and adds cmd code
        at the beginning.
        """
        if isinstance(self.data, ctap2.GetInfo):
            data = chr(Ctap2.CMD.GET_INFO).encode()
        elif isinstance(self.data, ctap2.ClientPIN):
            data = chr(Ctap2.CMD.CLIENT_PIN).encode() + cbor.encode(
                self.data.to_dict())
        elif isinstance(self.data, ctap2.GetAssertion):
            data = chr(Ctap2.CMD.GET_ASSERTION).encode() + cbor.encode(
                self.data.to_dict())
        elif isinstance(self.data, ctap2.MakeCredential):
            data = chr(Ctap2.CMD.MAKE_CREDENTIAL).encode() + cbor.encode(
                self.data.to_dict())
        elif isinstance(self.data, InvalidRequest):
            data = bytes(self.data)
            logging.getLogger('ctap').error("Invalid CBOR request : %s",
                                             self.data)
        else:
            logging.getLogger('ctap').error("CBOR request unknown type: %s",
                                             self.data)
            raise NotImplementedError(f"{self.data}")
        return data

    @property
    def name(self) -> str:
        """
        Return snake_case name of request.
        """
        cls_name = self.data.__class__.__name__
        return re.sub('(?!^)([A-Z]+)', r'_\1', cls_name).lower()


CTAP1_DISABLE_PATHS = [
    '/etc/qubes/ctap1-disable',
    '/usr/local/etc/qubes/ctap1-disable',
]
CTAP2_DISABLE_PATHS = [
    '/etc/qubes/ctap2-disable',
    '/usr/local/etc/qubes/ctap2-disable',
]
