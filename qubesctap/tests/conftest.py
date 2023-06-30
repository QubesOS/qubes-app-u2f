# coding=utf-8
#
# The Qubes OS Project, https://www.qubes-os.org
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
import contextlib
import io
import sys

from fido2.ctap import CtapError
from fido2.ctap1 import ApduError, RegistrationData, SignatureData
from fido2.ctap2 import AttestationResponse, AssertionResponse

from qubesctap import ctap2
from qubesctap.ctap1 import Register, Authenticate
from qubesctap.ctap2 import MakeCredential, GetAssertion, GetInfo, ClientPIN,\
    Info
from qubesctap.protocol import InvalidRequest, RequestWrapper, \
    ApduResponseWrapper, CborResponseWrapper


@contextlib.contextmanager
def mocked_stdio(stdin=b''):
    """Context which substitutes :obj:`sys.stdin` and :obj:`sys.stdout`

    Within the context, each of them is a :class:`io.TextIOWrapper` over
    :class:`io.BytesIO`. You may pass an initial state of stdin as an argument.
    Retrieve stdout from ``sys.stdin.buffer.getvalue()``.

    >>> with mocked_stdio(b'spam'):
    ...     print('eggs')
    ...     assert sys.stdin.read() == 'spam'
    ...     assert sys.stdout.buffer.getvalue() == b'eggs'
    """

    sys.stdin = io.TextIOWrapper(io.BytesIO(stdin))
    sys.stdout = io.TextIOWrapper(io.BytesIO(), write_through=True)
    try:
        yield
    finally:
        sys.stdin = sys.__stdin__
        sys.stdout = sys.__stdout__


stub_cmd = {
    "MakeCredential": {"request": {"class": MakeCredential, "hex": "01a801582065f9496dadc972a527a23dcfd06ce45f1d24f34f8472edb15bd00040af897d0a02a26269646b776562617574686e2e696f646e616d656b776562617574686e2e696f03a3626964581f62486871636d6c7a6447466a6332527a5a6d527a59325a6a596d3932613273646e616d65776c786a726973746163736473666473636663626f766b6b6b646973706c61794e616d65776c786a726973746163736473666473636663626f766b6b0482a263616c672664747970656a7075626c69632d6b6579a263616c6739010064747970656a7075626c69632d6b657906a16b6372656450726f746563740207a162726bf50858207b9a039f3c53298e98ea0ae88de4843dfd9f0f0307a8f06b8ff607b9b7a063b10902"},
                       "response": {"class": AttestationResponse, "hex": "a301667061636b65640258c40021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae124100000003f8a011f38c0a4d15800617111f9edc7d004060a386206a3aacecbdbb22d601853d955fdc5d11adfbd1aa6a950d966b348c7663d40173714a9f987df6461beadfb9cd6419ffdfe4d4cf2eec1aa605a4f59bdaa50102032620012158200edb27580389494d74d2373b8f8c2e8b76fa135946d4f30d0e187e120b423349225820e03400d189e85a55de9ab0f538ed60736eb750f5f0306a80060fe1b13010560d03a363616c6726637369675847304502200d15daf337d727ab4719b4027114a2ac43cd565d394ced62c3d9d1d90825f0b3022100989615e7394c87f4ad91f8fdae86f7a3326df332b3633db088aac76bffb9a46b63783563815902bb308202b73082019fa00302010202041d31330d300d06092a864886f70d01010b0500302a3128302606035504030c1f59756269636f2050726576696577204649444f204174746573746174696f6e301e170d3138303332383036333932345a170d3139303332383036333932345a306e310b300906035504061302534531123010060355040a0c0959756269636f20414231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3127302506035504030c1e59756269636f205532462045452053657269616c203438393736333539373059301306072a8648ce3d020106082a8648ce3d030107034200047d71e8367cafd0ea6cf0d61e4c6a416ba5bb6d8fad52db2389ad07969f0f463bfdddddc29d39d3199163ee49575a3336c04b3309d607f6160c81e023373e0197a36c306a302206092b0601040182c40a020415312e332e362e312e342e312e34313438322e312e323013060b2b0601040182e51c0201010404030204303021060b2b0601040182e51c01010404120410f8a011f38c0a4d15800617111f9edc7d300c0603551d130101ff04023000300d06092a864886f70d01010b050003820101009b904ceadbe1f1985486fead02baeaa77e5ab4e6e52b7e6a2666a4dc06e241578169193b63dadec5b2b78605a128b2e03f7fe2a98eaeb4219f52220995f400ce15d630cf0598ba662d7162459f1ad1fc623067376d4e4091be65ac1a33d8561b9996c0529ec1816d1710786384d5e8783aa1f7474cb99fe8f5a63a79ff454380361c299d67cb5cc7c79f0d8c09f8849b0500f6d625408c77cbbc26ddee11cb581beb7947137ad4f05aaf38bd98da10042ddcac277604a395a5b3eaa88a5c8bb27ab59c8127d59d6bbba5f11506bf7b75fda7561a0837c46f025fd54dcf1014fc8d17c859507ac57d4b1dea99485df0ba8f34d00103c3eef2ef3bbfec7a6613de"}},
    "GetAssertion": {"request": {"class": GetAssertion, "hex": "02a5016b776562617574686e2e696f025820addf18581bffd2a73fd6ba468fce7f482535cb3f8b4aa2708c53aff2b4496e080381a26269645840d2d216c4ac2b76c64125cbc7eb6d7c384d96c9acb00a407af90133a2f1c15703af33a5ce652b1d624433dea32096422ff2787aeb92f25aab863e5aa592070af264747970656a7075626c69632d6b6579065820222246d8d31c6047014a61a8f5532d534b9ad2622fcd4619bf57014ebebe15f60702"},
                       "response": {"class": AssertionResponse, "hex": "a301a26269645840fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b1578364747970656a7075626c69632d6b65790258250021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12010000001d035846304402206765cbf6e871d3af7f01ae96f06b13c90f26f54b905c5166a2c791274fc2397102200b143893586cc799fba4da83b119eaea1bd80ac3ce88fcedb3efbd596a1f4f63"}},
    "GetInfo": {"request": {"class": GetInfo, "hex": "04"},
                       "response": {"class": Info, "hex": "aa0182665532465f5632684649444f5f325f3002826375766d6b686d61632d7365637265740350f8a011f38c0a4d15800617111f9edc7d04a462726bf5627570f564706c6174f469636c69656e7450696ef4051904b006810109800cf40d041000"}},
    "ClientPIN": {"request": {"class": ClientPIN, "hex": "06a40102020503a5010203381820012158207bac22d4791f58c2afe486e9c73d22f6d8f338274c8a8b86efd3ab228fde625a2258209a44d71d67249b800d31ef7d2c38760a77d6d4198b1ef40b9e38fe58987db4d9065820b9faac4c7c7dbd0983da564693c07a9aa00a0e5a8e896382461e95d25fdd1671"},
                       "response": {"class": ctap2.ClientPINResponse, "hex": "a1025830540718a8a0fdb5c3c8914afc4eb51fc5ef94b33c263ab251a9a48f14c87cd92bb90fb360b69553e1088b61a3c809be66"}},
    "Register": {"request": {"class": Register, "hex": "00010300000040e03ee56cb6d67d834c7b826d105fc2bb7f4caf9cbc783a2fd967aea4ea8b7773c46cef82ad1b546477591d008b08759ec3e6d2ecb4f39474bfea6969925d03b70000"},
                       "response": {"class": RegistrationData, "hex": "0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871"}},
    "Authenticate": {"request": {"class": Authenticate, "hex": "000203000000815c868d65fa62d5053d13d9b50c032f1feb164af1bbd8ccc84caa76ec08945f03c46cef82ad1b546477591d008b08759ec3e6d2ecb4f39474bfea6969925d03b740162e95477ff9214dbbfdbda3580f27ba2d4917db9d2a3ed7a1a4d4caf6ca9b88d12e2134532d7e010f24ba1c9bb3b6c7c01574312baa738ee4bb76d4e89164780000"},
                       "response": {"class": SignatureData, "hex": "0100000001304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272ec10047a923f"}},
    "CtapError": {"request": {"class": InvalidRequest, "hex": "dead"},
                       "response": {"class": CtapError, "hex": "beef"}},
    "ApduError": {"request": {"class": InvalidRequest, "hex": "dead"},
                           "response": {"class": ApduError, "hex": "beef"}},
}


def get_request(action: str):
    return RequestWrapper.from_bytes(
        bytes.fromhex(stub_cmd[action]["request"]["hex"])
    )

def get_request_bytes(action: str):
    return bytes.fromhex(stub_cmd[action]["request"]["hex"])

def get_request_class(action: str):
    return stub_cmd[action]["request"]["class"]

def get_qrexec_arg(action: str):
    args = {
        "Register": "0be41a3e5c92fc823198ea279122a26a",
        "GetAssertion": "c9310b6c3d33b1e86c070ed9c487632a",
        "Authenticate": "92b0828988bf2679992cc5fe5b03d23f",
        "MakeCredential": "682cb256ec6e41a548eb4bf2d822869a"}
    return args[action]


def get_response(action: str):
    if action in ("Register", "Authenticate"):
        return ApduResponseWrapper.from_bytes(
            get_response_bytes(action),
            expected_type=get_response_class(action)
            )
    return CborResponseWrapper.from_bytes(
        get_response_bytes(action),
        expected_type=get_response_class(action)
    )

def get_response_bytes(action: str):
    response = bytes.fromhex(stub_cmd[action]["response"]["hex"])
    if action in ("Register", "Authenticate", "ApduError"):
        return response + b"\x90\x00"
    return b"\x00" + response


def get_response_class(action: str):
    return stub_cmd[action]["response"]["class"]


class FakeQrexecClient:
    def __init__(self, returncode=0, stdout=b'', stderr=b''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr =stderr

    async def communicate(self, _request: bytes):
        return self.stdout, self.stderr
