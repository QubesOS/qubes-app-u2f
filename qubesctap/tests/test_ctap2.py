# coding=utf-8
#
# The Qubes OS Project, https://www.qubes-os.org
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
from fido2 import cbor

from qubesctap.ctap2 import Ctap2Request, ClientPIN
from qubesctap.protocol import RequestWrapper


def _make_credential(rp: dict) -> bytes:
    return bytes([0x01]) + cbor.encode({
        1: b"\x00" * 32,
        2: rp,
        3: {"id": b"user", "name": "user"},
        4: [{"alg": -7, "type": "public-key"}],
        7: {"rk": True},
    })


def test_makecredential_rp_without_name_defaults_to_id():
    """Firefox omits rp.name; fido2 marks it required. It must parse, with
    name defaulting to the (always present, non-empty) rp id."""
    req = Ctap2Request.from_bytes(_make_credential({"id": "webauthn.io"}))
    assert req.rp.id == "webauthn.io"
    assert req.rp.name == "webauthn.io"


def test_makecredential_rp_with_name_is_preserved():
    req = Ctap2Request.from_bytes(
        _make_credential({"id": "webauthn.io", "name": "Example"}))
    assert req.rp.name == "Example"


def test_makecredential_rp_name_reserializes_as_text_string():
    """The re-serialised rp.name (what the proxy forwards) must be a text
    string, not [] -- fido2 maps an empty string to [] via a vacuous all(),
    which the token rejects with CTAP2_ERR_CBOR_UNEXPECTED_TYPE (0x11)."""
    wrapper = RequestWrapper.from_bytes(_make_credential({"id": "webauthn.io"}))
    rp = cbor.decode(bytes(wrapper)[1:])[2]
    assert rp["name"] == "webauthn.io"
    assert isinstance(rp["name"], str)


def _client_pin(extra: dict) -> bytes:
    base = {1: 2, 2: 0x09, 3: {1: 2}, 6: b"\xcc" * 32}
    base.update(extra)
    return bytes([0x06]) + cbor.encode(base)


def test_clientpin_permissions_use_cbor_keys_9_and_10():
    """authenticatorClientPIN skips CBOR keys 0x07/0x08: permissions is 0x09
    and rpId is 0x0A. The positional index+1 map would use 7/8 and silently
    drop them, breaking PIN on CTAP2.1 (pinUvAuthToken) authenticators."""
    wrapper = RequestWrapper.from_bytes(
        _client_pin({9: 0x03, 10: "webauthn.io"}))
    req = wrapper.data
    assert isinstance(req, ClientPIN)
    assert req.permissions == 0x03
    assert req.permissions_rpid == "webauthn.io"

    encoded = cbor.decode(bytes(wrapper)[1:])
    assert encoded[9] == 0x03
    assert encoded[10] == "webauthn.io"
    assert 7 not in encoded and 8 not in encoded


def test_clientpin_get_pin_token_without_permissions_unaffected():
    """Legacy getPinToken (0x05) carries no permissions; must still parse."""
    req = Ctap2Request.from_bytes(
        bytes([0x06]) + cbor.encode({1: 2, 2: 0x05, 3: {1: 2}, 6: b"\xcc" * 16}))
    assert isinstance(req, ClientPIN)
    assert req.sub_cmd == 0x05
    assert req.permissions is None
    assert req.permissions_rpid is None
