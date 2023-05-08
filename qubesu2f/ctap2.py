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

"""Protocol CTAP2 classes and structures.

.. seealso::
    https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html
        (June 21, 2022)
"""
from dataclasses import dataclass, fields, Field
from typing import Optional, Any, Mapping, List, Iterable, Hashable, \
    Dict

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2.base import Ctap2, Info, args, _CborDataObject, \
    AttestationResponse, AssertionResponse
from fido2.webauthn import PublicKeyCredentialRpEntity

from qubesu2f.util import qrexec_arg


@dataclass(eq=False, frozen=True)
class Ctap2Dataclass(_CborDataObject):
    """
    Mapping representing a CTAP2 request/response.
    """

    @classmethod
    def _get_field_key(cls, field: Field) -> int:
        return fields(cls).index(field) + 1

    @classmethod
    def from_dict(
            cls, data: Optional[Mapping[int, Any]]
    ) -> "Ctap2Dataclass":
        """
        Creates an instance of Ctap2Dataclass from a dictionary.

        The keys in the dictionary are expected to match the CBOR keys
        for the fields in the class.
        """
        assert data is not None
        kwargs: Dict[Hashable, Any] = \
            {
                attr.name: None for attr in fields(cls)
                if hasattr(attr.type, "__args__")
                # Set None for Optional by default
                and attr.type.__args__[-1] is type(None)
            }
        for field in fields(cls):
            if cls._get_field_key(field) in data:
                kwargs[field.name] = data[cls._get_field_key(field)]
        return cls(**kwargs)

    def to_dict(self) -> dict:
        """
        Returns a dictionary representation of the Ctap2Dataclass instance,
        where the keys correspond to the CBOR keys for the fields in the class.
        """
        # pylint: disable=protected-access)
        result = {}
        cls = self.__class__
        for field in fields(cls):
            value = getattr(self, field.name)
            if value is not None:
                result[cls._get_field_key(field)] = value
        return result


@dataclass(eq=False, frozen=True)
class Ctap2Request(Ctap2Dataclass):
    """
    Mapping representing a CTAP2 request.

    It is used to serialize/deserialize the request data to/from CBOR.
    """

    def execute(self, ctap: Ctap2) -> Any:
        """
        It is used to execute the request on the CTAP device.
        """
        raise NotImplementedError()

    @staticmethod
    def from_bytes(untrusted_data: bytes) -> "Ctap2Request":
        """
        Creates an instance of Ctap2Dataclass from a untrusted_bytes.

        The `untrusted_data` are decoded as CBOR message and then parsed
        as request class.
        """
        req_type, untrusted_cbor = untrusted_data[0], untrusted_data[1:]

        if req_type not in Ctap2RequestRegister.register:
            raise TypeError(
                f"Unknown request type code: {req_type!r}"
                f" with cbor data: {untrusted_cbor!r}"
            )
        req_cls = Ctap2RequestRegister.register[req_type]
        cbor_request = cbor.decode(untrusted_cbor) if untrusted_cbor else {}
        request = req_cls.from_dict(cbor_request)

        return request


class Ctap2RequestRegister:
    """Register of all CTAP2 request classes with class decorator."""
    # pylint: disable=missing-function-docstring,too-few-public-methods

    register: dict = {}

    @staticmethod
    def add(cmd: int):
        def add_to_dict(solver):
            if cmd in Ctap2RequestRegister.register:
                raise KeyError
            Ctap2RequestRegister.register[cmd] = solver
            return solver

        return add_to_dict


@Ctap2RequestRegister.add(Ctap2.CMD.GET_INFO)
@dataclass(eq=False, frozen=True)
class GetInfo(Ctap2Request):
    """
    Represents a CTAP2 request to get information from a device.

    Attributes:
    -----------
    GetInfo command do not contain any information.
    """
    def execute(self, ctap: Ctap2) -> Info:
        """
        Sends the CMD.GET_INFO command to the device and returns the response
        as an `Info` object.
        """
        response = Info.from_dict(ctap.send_cbor(Ctap2.CMD.GET_INFO))
        return response


@Ctap2RequestRegister.add(Ctap2.CMD.MAKE_CREDENTIAL)
@dataclass(eq=False, frozen=True)
class MakeCredential(Ctap2Request):
    """
    Represents a CTAP2 request to create a new credential on a device.

    Attributes:
    -----------
    client_data_hash: bytes
        A hash of the client data used in the credential creation process.
    rp: PublicKeyCredentialRpEntity
        An instance of the `PublicKeyCredentialRpEntity` class representing
        the relying party.
    user: dict
        A dictionary representing the user associated with the credential.
    pub_key_cred_params: Sequence[dict]
        A sequence of dictionaries representing the desired public key
        credential parameters.
    exclude_list: Optional[dict]
        A dictionary representing the excluded credentials.
    extensions: Optional[dict]
        A dictionary representing the extensions.
    options: Optional[dict]
        A dictionary representing the options.
    pin_uv_auth_param: Optional[bytes]
        A parameter used in the PIN/UV authorization process.
    pin_uv_auth_protocol: Optional[int]
        The protocol used in the PIN/UV authorization process.
    enterprise_attestation: Optional[int]
        An optional flag used in enterprise attestation.
    """
    # pylint: disable=invalid-name,too-many-instance-attributes
    client_data_hash: bytes
    rp: PublicKeyCredentialRpEntity
    user: dict
    pub_key_cred_params: List[Mapping[str, Any]]
    exclude_list: Optional[List[Mapping[str, Any]]]
    extensions: Optional[dict]
    options: Optional[dict]
    pin_uv_auth_param: Optional[bytes]
    pin_uv_auth_protocol: Optional[int]
    enterprise_attestation: Optional[int]

    def execute(self, ctap: Ctap2) -> AttestationResponse:
        """
        Sends the `make_credential` command to the device and returns
        the response.
        """
        response = ctap.make_credential(
            self.client_data_hash,
            self.rp,
            self.user,
            self.pub_key_cred_params,
            self.exclude_list,
            self.extensions,
            self.options,
            self.pin_uv_auth_param,
            self.pin_uv_auth_protocol,
            self.enterprise_attestation,
        )
        return response


@Ctap2RequestRegister.add(Ctap2.CMD.GET_ASSERTION)
@dataclass(eq=False, frozen=True)
class GetAssertion(Ctap2Request):
    """
    Represents a CTAP2 request to get assertion from a device.

    Attributes:
        rp_id: str
            The relying party ID.
        client_data_hash: bytes
            The client data hash.
        allow_list: Optional[Sequence[dict]]
            The list of public key credentials allowed to be used
            in the assertion process.
        extensions: Optional[dict]
            The list of CTAP extensions to be used in the assertion process.
        options: Optional[dict]
            The list of options to be used in the assertion process.
        pin_uv_auth_param: Optional[bytes]
            The PIN/UV authorization parameter.
        pin_uv_auth_protocol: Optional[int]
            The PIN/UV authorization protocol.

    Methods:
        execute(ctap) -> Any:

        qrexec_args() -> Any:

    """
    rp_id: str
    client_data_hash: bytes
    allow_list: Optional[List[Mapping[str, Any]]]
    extensions: Optional[dict]
    options: Optional[dict]
    pin_uv_auth_param: Optional[bytes]
    pin_uv_auth_protocol: Optional[int]

    def execute(self, ctap: Ctap2) -> AssertionResponse:
        """
        Executes a get assertion request to the specified CTAP device
        and returns the response.
        """
        response = ctap.get_assertion(
            rp_id=self.rp_id,
            client_data_hash=self.client_data_hash,
            allow_list=self.allow_list,
            extensions=self.extensions,
            options=self.options,
            pin_uv_param=self.pin_uv_auth_param,
            pin_uv_protocol=self.pin_uv_auth_protocol,
        )
        return response

    def qrexec_args(self) -> Iterable[str]:
        """
        Yields the qrexec arguments to be used in the assertion process.
        """
        if self.allow_list is None:
            return
        for cred in self.allow_list:
            yield qrexec_arg(cred['id'])


@dataclass(eq=False, frozen=True)
class ClientPINResponse(Ctap2Dataclass):
    """
    Represents the response returned by the client PIN protocol.

    Attributes:
        key_agreement: Optional[Mapping[int, Any]]
            A dictionary containing a key agreement value.
        pin_uv_auth_param: Optional[bytes]
            A byte string containing the PIN/UV auth parameter.
        pin_retries: Optional[int]
            The number of PIN retries remaining.
        power_cycle_state: Optional[bool]
            Whether the authenticator is currently in power cycle state.
        uv_retries: Optional[int]
            The number of UV retries remaining.
    """
    key_agreement: Optional[Mapping[int, Any]]
    pin_uv_auth_param: Optional[bytes]
    pin_retries: Optional[int]
    power_cycle_state: Optional[bool]
    uv_retries: Optional[int]


@Ctap2RequestRegister.add(Ctap2.CMD.CLIENT_PIN)
@dataclass(eq=False, frozen=True)
class ClientPIN(Ctap2Request):
    """
    A class representing a Client PIN protocol request.

    Attributes
    ----------
    pin_uv_protocol : int
        The version of the PIN protocol to use.
    sub_cmd : int
        The subcommand for the PIN protocol request.
    key_agreement : Optional[Mapping[int, Any]]
        The key agreement to use for the PIN protocol request.
    pin_uv_param : Optional[bytes]
        The parameter to use for the PIN protocol request.
    new_pin_enc : Optional[bytes]
        The new PIN to use for the PIN protocol request.
    pin_hash_enc : Optional[bytes]
        The encrypted PIN hash to use for the PIN protocol request.
    permissions : Optional[int]
        The permission for the PIN protocol request.
    permissions_rpid : Optional[str]
        The permission RP ID for the PIN protocol request.
    """
    # pylint: disable=too-many-instance-attributes
    pin_uv_protocol: int
    sub_cmd: int
    key_agreement: Optional[Mapping[int, Any]]
    pin_uv_param: Optional[bytes]
    new_pin_enc: Optional[bytes]
    pin_hash_enc: Optional[bytes]
    permissions: Optional[int]
    permissions_rpid: Optional[str]

    def execute(self, ctap: Ctap2) -> ClientPINResponse:
        """
        Sends the Client PIN protocol request to the authenticator and
        returns the response.
        """
        response = ctap.send_cbor(
            Ctap2.CMD.CLIENT_PIN,
            args(
                self.pin_uv_protocol,
                self.sub_cmd,
                self.key_agreement,
                self.pin_uv_param,
                self.new_pin_enc,
                self.pin_hash_enc,
                None,
                None,
                self.permissions,
                self.permissions_rpid,
            )
        )
        parsed = ClientPINResponse.from_dict(response)  # type: ignore
        if not isinstance(parsed, ClientPINResponse):
            raise CtapError(1)
        return parsed
