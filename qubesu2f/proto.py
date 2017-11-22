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
'''Protocol classes and structures.

.. seealso::
    https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
        FIDO U2F Raw Message Formats v1.2 (2017-04-11)

    https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html
        FIDO U2F HID Protocol Specification v1.2 (2017-04-11)
'''
# pylint: enable=line-too-long

import contextlib
import ctypes
import hashlib
import io
import logging
import sys

from . import const
from . import util

class ResponseAPDUMeta(type):
    '''Metaclass for :py:class:`ResponseAPDU`'''
    # pylint: disable=no-self-argument
    _known_sw = {}
    def __init__(cls, name, bases, dct):
        super().__init__(name, bases, dct)

        sw = dct.get('APDU_SW', const.U2F_SW.NO_ERROR)
        if sw != const.U2F_SW.NO_ERROR:
            assert sw not in cls._known_sw
            cls._known_sw[sw] = cls

        # pylint: disable=access-member-before-definition
        if not cls.__doc__ and sw is not None:
            cls.__doc__ = const.U2F_SW_MSG[sw]

    def get_class_for_sw(cls, untrusted_sw):
        '''Given Status Word, return appropriate class

        :param int untrusted_sw: Status Word
        :rtype ResponseAPDUMeta:
        :raises ValueError: if untrusted_sw is not in :py:class:`const.U2F_SW`
        :raises KeyError: either class is not defined, or *untrusted_sw* is
            :py:attr:`const.U2F_SW.NO_ERROR` (``0x9000``), since it is
            forbidden from appearing in cls._known_sw, as the exact class
            should be explicitly requested when reading
        '''

        return cls._known_sw[const.U2F_SW.from_buffer(untrusted_sw)]

# ResponseAPDU is somewhat convoluted, because its instances are used in three
# cases:
#  1. When creating APDU from parameters.
#  2. When parsing APDU from buffer.
#  3. As an exception, raised from somewhere (and sent as-is).
#
# In 1. this is easy, and verification has value only as sanity checking.
# In 3. this is only slightly harder, untrusted_sw is None and taken from
# class' definition (that's the reasoning under untrusted_sw in this case), so
# raise APDUWrongSomethingError() just works and you can catch the exception
# and post it itself as bytes.
#
# The tricky case is 2. Typically one uses classmethod from_buffer() called on
# subclass of ResponseAPDU (like ResponseAPDUAuthenticate, even better
# command_apdu.APDU_RESPONSE, so you don't have to guess). It should return
# either ResponseAPDUAuthenticate, or one of the error classes.
#
# This is also the reason for that mess in ResponseAPDU.__new__().

# [<response-data>] SW1 SW2
class ResponseAPDU(metaclass=ResponseAPDUMeta):
    '''Abstract class for any response APDU.

    :param bytes untrusted_sw: The 2-octet status word.
    :param bytes untrusted_response_data: The response data.
    '''
    APDU_SW = const.U2F_SW.NO_ERROR

    def __new__(cls, *args, untrusted_sw=None, **kwargs):
        logging.debug('ResponseAPDU.__new__('
            'cls=%r, *args=%r, untrusted_sw=%r, **kwargs=%r)',
            cls, args, untrusted_sw, kwargs)

        newcls = cls
        # the second clause is in case we expect a particular response,
        # but got error instead
        if (untrusted_sw not in (None, const.U2F_SW.NO_ERROR)
                and cls.APDU_SW == const.U2F_SW.NO_ERROR):
            # pylint: disable=no-member
            newcls = cls.get_class_for_sw(untrusted_sw=untrusted_sw)

        logging.debug('ResponseAPDU.__new__ newcls=%r', newcls)

        # "object.__new__() is not safe, use Exception.__new__()", but we can't
        # have Exception as first base class, because Exception.__init__ does
        # not call super().__init__
        superobj = Exception if issubclass(newcls, Exception) else object
        logging.debug('ResponseAPDU.__new__ superobj=%r', superobj)
        self = superobj.__new__(newcls)

        # If cls is strict subclass of ResponseAPDU and error happened, the
        # resulting object is not of type cls and __init__ will not be called
        # as per Python's object model.
        if not isinstance(self, cls):
            logging.debug('ResponseAPDU.__new__ calling __init__ directly')
            self.__init__(*args, untrusted_sw=untrusted_sw, **kwargs)

        return self


    def __init__(self, *args, untrusted_sw, untrusted_response_data=b'',
            **kwargs):
        logging.debug('ResponseAPDU.__init__('
            '*args=%r, untrusted_sw=%r, untrusted_response_data=%r, kwargs=%r)',
            args, untrusted_sw, untrusted_response_data, kwargs)
        super().__init__(*args, **kwargs)

        try:
            logging.debug('ResponseAPDU.__init__ sw')
            #: the status word, as int (big endian)
            self.sw = self.verify_sw(untrusted_sw=untrusted_sw)

            logging.debug('ResponseAPDU.__init__ response_data')
            #: the response data
            self.response_data = self.verify_response_data(
                untrusted_response_data=untrusted_response_data)

        except APDUError:
            logging.debug('ResponseAPDU.__init__ APDUError')
            raise

        except:
            # XXX We have a problem here. From token's POV the transaction is
            # already completed and we have to return something to the browser.
            # But we can do nothing about that. Maybe a custom error would be
            # in order?
            logging.debug('ResponseAPDU.__init__ APDUWrongDataError')
            raise APDUWrongDataError()


    def __bytes__(self):
        return self.response_data + bytes(self.sw)

    def hexdump_response_data(self):
        # pylint: disable=missing-docstring
        return util.hexlify(self.response_data)

    def hexdump(self):
        '''Retur a hexdump of the packet.'''
        return ' '.join(filter(bool,
            (self.hexdump_response_data(), util.hexlify(bytes(self.sw)))))

    # pylint: disable=no-self-use

    def verify_response_data(self, *, untrusted_response_data):
        '''Verify the untrusted response data.

        In abstract class, this asserts that *untrusted_response_data* is
        empty. The subclass should override this with appropriate
        implementation.
        '''
        if untrusted_response_data == b'':
            response_data = untrusted_response_data
            return response_data

        raise NotImplementedError()

    def verify_sw(self, *, untrusted_sw):
        '''Verify the untrusted Status Word.'''
        untrusted_sw = const.U2F_SW.from_buffer(untrusted_sw)
        assert untrusted_sw == self.APDU_SW
        sw = untrusted_sw
        return sw

    # pylint: enable=no-self-use

    def raise_for_sw(self):
        '''Raise an exception if the status word indicates an error.

        That is, it is not :py:const:`const.U2F_SW.NO_ERROR`.'''
        pass

    @classmethod
    def from_buffer(cls, untrusted_data):
        '''Read the response from raw data

        :param bytes untrusted_data: the buffer

        Do not use this method directly. Instead use it as a classmethod on the
        correct subclass, as there is no indication in the data, what kind of
        response this is.
        '''
        logging.debug('ResponseAPDU.from_buffer(cls=%r, untrusted_data=%r)',
            cls, untrusted_data)
        return cls(
            untrusted_response_data=untrusted_data[:-2],
            untrusted_sw=untrusted_data[-2:])


class APDUError(ResponseAPDU, Exception):
    '''Base class for Status Word exceptions'''

    APDU_SW = const.U2F_SW.NO_DIAGNOSIS

    def __init__(self, *args, untrusted_sw=None, **kwargs):
        logging.debug('APDUError.__init__('
            '*args=%r, untrusted_sw=%r, **kwargs=%r)',
            args, untrusted_sw, kwargs)

        if untrusted_sw is None:
            untrusted_sw = bytes(self.APDU_SW)
        # else, it will be checked in .verify_sw() by ResponseAPDU.__init__()

        super().__init__(*args, untrusted_sw=untrusted_sw, **kwargs)

    def raise_for_sw(self):
        raise self

# pylint: disable=missing-docstring
# (the docstrings are added in metaclass)

class APDUConditionsNotSatisfiedError(APDUError):
    APDU_SW = const.U2F_SW.CONDITIONS_NOT_SATISFIED

class APDUWrongDataError(APDUError):
    APDU_SW = const.U2F_SW.WRONG_DATA

class APDUWrongLengthError(APDUError):
    APDU_SW = const.U2F_SW.WRONG_LENGTH

class APDUCLANotSupported(APDUError):
    APDU_SW = const.U2F_SW.CLA_NOT_SUPPORTED

class APDUINSNotSupported(APDUError):
    APDU_SW = const.U2F_SW.INS_NOT_SUPPORTED

class APDUExecutionError(APDUError):
    APDU_SW = const.U2F_SW.EXECUTION_ERROR

class APDUWrongP1P2Error(APDUError):
    APDU_SW = const.U2F_SW.WRONG_P1_P2

# pylint: enable=missing-docstring

class ResponseAPDURegister(ResponseAPDU):
    '''Response for U2F_REGISTER'''
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # this function is not security-critical, the data is already verified
        kh_offset = 1 + const.P256_POINT_SIZE + 1
        self._key_handle_len = self.response_data[kh_offset - 1]
        self.key_handle = (
            self.response_data[kh_offset:kh_offset+self._key_handle_len])

        x509_offset = kh_offset + self._key_handle_len + 1
        self._x509_len = self.response_data[x509_offset - 1]

    def verify_response_data(self, *, untrusted_response_data):
        offset = 0

        logging.debug('offset=%r (register id)', offset)
        assert untrusted_response_data[offset] == const.U2F_REGISTER_ID
        offset += 1

        logging.debug('offset=%r (pubkey)', offset)
        # P-256 point not verified
        offset += const.P256_POINT_SIZE

        logging.debug('offset=%r (khlen)', offset)
        key_handle_len = untrusted_response_data[offset]
        assert key_handle_len <= const.MAX_KH_SIZE
        offset += 1 + key_handle_len

        logging.debug('offset=%r (x509)', offset)
        x509_len = get_der_length(
            untrusted_der_data=untrusted_response_data[offset:])
        offset += x509_len

        # [U2FRawMsgs] says ECDSA signature is 71-73 bytes;
        # this is not correct, other lengths are possible
        logging.debug('offset=%r (sig)', offset)
        ecdsa_sig_len = get_der_length(
            untrusted_der_data=untrusted_response_data[offset:])
        offset += ecdsa_sig_len

        logging.debug('offset=%r (end)', offset)
        assert offset == len(untrusted_response_data)

        response_data = untrusted_response_data
        return response_data

    def hexdump_response_data(self):
        return util.hexlify_with_parition(self.response_data,
            1, const.P256_POINT_SIZE, 1, self._key_handle_len, self._x509_len)


class ResponseAPDUAuthenticate(ResponseAPDU):
    '''Response to U2F_AUTHENTICATE'''
    def verify_response_data(self, *, untrusted_response_data):
        const.U2F_AUTH_USER_PRESENCE(untrusted_response_data[0])  # ValueError

        # bytes 1-4: counter; relying party checks it, but we don't care

        ecdsa_sig_len = get_der_length(
            untrusted_der_data=untrusted_response_data[5:])
        assert len(untrusted_response_data) == 5 + ecdsa_sig_len

        response_data = untrusted_response_data
        return response_data

    def hexdump_response_data(self):
        return util.hexlify_with_parition(self.response_data, 1, 4)


class ResponseAPDUVersion(ResponseAPDU):
    '''Response to U2F_VERSION'''
    def verify_response_data(self, *, untrusted_response_data):
        if isinstance(untrusted_response_data, str):
            # got that from constant, not from bytes originating from elsewhere
            response_data = untrusted_response_data
        else:
            response_data = untrusted_response_data.decode('ascii',
                errors='strict')
        return response_data


class CommandAPDUMeta(type):
    '''Metaclass for :class:`CommandAPDU`'''
    _known_ins = {}
    def __init__(cls, name, bases, dct):
        super().__init__(name, bases, dct)
        ins = dct['APDU_INS']
        assert ins not in cls._known_ins
        cls._known_ins[ins] = cls

    def get_class_for_ins(cls, untrusted_ins):
        '''Given INS, return appropriate class

        :param int sw: Status Word
        :rtype APDUErrorMeta:
        '''
        # will raise KeyError if not already defined
        return cls._known_ins[untrusted_ins]

# CLA INS P1 P2 [0] [Lc1 Lc2 <request-data>] [Le1 Le2]
class CommandAPDU(metaclass=CommandAPDUMeta):
    '''Abstract class for command (request) APDU'''
    # != to any int, so fails .verify_ins() unless overridden in subclass
    APDU_INS = None

    def __new__(cls, untrusted_cla, untrusted_ins, untrusted_p1,
            untrusted_p2, untrusted_request_data, untrusted_le):
        # pylint: disable=too-many-arguments,unused-argument
        if cls.APDU_INS is None:
            # pylint: disable=no-member
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

        except APDUError:
            raise

        except Exception:
            self.log.error('__init__ exception:', exc_info=True)
            raise APDUINSNotSupported()

    def _assemble(self, write):
        write(bytes((self.cla,)))
        write(bytes((self.ins,)))
        write(bytes((self.p1,)))
        write(bytes((self.p2,)))

        if self.request_data or self.le:
            # HID always uses extended length APDU encoding [U2FHID 2]
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
        '''Return a hexdump of the packet'''
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

    # pylint: disable=no-self-use

    def verify_cla(self, *, untrusted_cla):
        '''Verify CLA octet.

        This accepts only 0x00. Subclass may overload this method and provide
        appropriate implementation.
        '''
        if untrusted_cla != 0x00:
            raise APDUCLANotSupported(untrusted_cla)
        cla = untrusted_cla
        return cla

    def verify_ins(self, *, untrusted_ins):
        '''Verify INS octet.

        This checks if the argument matches respective
        :const:`CommandAPDU.APDU_INS` value for the class.
        '''
        untrusted_ins = const.U2F(untrusted_ins)
        assert untrusted_ins == type(self).APDU_INS
        ins = untrusted_ins
        return ins

    def verify_p1(self, *, untrusted_p1):
        '''Verify P1 octet.

        This accepts only 0x00. Subclass may overload this method and provide
        appropriate implementation.
        '''
        assert untrusted_p1 == 0x00
        p1 = untrusted_p1
        return p1

    def verify_p2(self, *, untrusted_p2):
        '''Verify P2 octet.

        This accepts only 0x00. Subclass may overload this method and provide
        appropriate implementation.
        '''
        assert untrusted_p2 == 0x00
        p2 = untrusted_p2
        return p2

    def verify_le(self, *, untrusted_le):
        '''Verify Le value.

        This does nothing. Subclass may overload this method and provide
        appropriate implementation.
        '''
#       assert untrusted_le == 0
        le = untrusted_le
        return le

    def verify_request_data(self, *, untrusted_request_data):
        '''Verify request-data.

        Subclass should overload this method with appropriate implementation.
        '''
        raise NotImplementedError()

    # pylint: enable=no-self-use

    @classmethod
    def from_buffer(cls, untrusted_data):
        '''Get a class' instance given :class:`bytes` object.

        :raises APDUError: upon validadion

        May be called from a particular subclass to ensure INS value.
        '''
        log = logging.getLogger(cls.__name__)
        log.debug('from_buffer(untrusted_data=%s)',
            util.hexlify(untrusted_data=untrusted_data))
        try:
            (untrusted_cla, untrusted_ins, untrusted_p1, untrusted_p2,
                ) = untrusted_data[:4]
        except ValueError:
            raise APDUWrongLengthError('data truncated at header')

        if len(untrusted_data) == 4:
            untrusted_request_data = b''
            untrusted_le = 0

        elif not untrusted_data[4] == 0:
            raise APDUWrongLengthError('expected extended length encoding')

        else:
            lc = util.u16n_read(untrusted_data, 5)
#           if lc == 0:
#               # legacy ISO-noncompliant APDU
#               raise APDUWrongLengthError('legacy APDU not supported')

            untrusted_request_data = untrusted_data[7:7+lc]
            if not len(untrusted_request_data) == lc:
                raise APDUWrongLengthError('data truncated at request_data')

            log.debug('from_buffer lc=%s untrusted_request_data=%s',
                lc, util.hexlify(untrusted_data=untrusted_request_data))

            if len(untrusted_data) == lc + 7:
                untrusted_le = 0
            elif len(untrusted_data) == lc + 9:
                untrusted_le = (
                    (util.u16n_read(untrusted_data, 7 + lc) - 1) % 0x10000 + 1)
            else:
                raise APDUWrongLengthError('trailing garbage')

        return cls(
            untrusted_cla=untrusted_cla,
            untrusted_ins=untrusted_ins,
            untrusted_p1=untrusted_p1,
            untrusted_p2=untrusted_p2,
            untrusted_request_data=untrusted_request_data,
            untrusted_le=untrusted_le)

    @classmethod
    def from_stream(cls, stream):
        '''Get a class' instance given ``read()``able string.

        :raises APDUError: upon validadion

        May be called from a particular subclass to ensure INS value.
        '''
        untrusted_data = stream.read(const.MAX_APDU_SIZE)

        # check for EOF
        untrusted_garbage = stream.read(1)
        if untrusted_garbage:
            raise APDUWrongLengthError('APDU too long')

        return cls.from_buffer(untrusted_data=untrusted_data)

class CommandAPDURegister(CommandAPDU):
    '''U2F_REGISTER'''
    # pylint: disable=too-few-public-methods
    APDU_INS = const.U2F.REGISTER
    APDU_RESPONSE = ResponseAPDURegister

    def verify_request_data(self, *, untrusted_request_data):
        assert len(untrusted_request_data
            ) == const.U2F_NONCE_SIZE + const.U2F_APPID_SIZE
        request_data = untrusted_request_data
        return request_data

    # this is unspecified, but at least chromium seems to include it
    def verify_p1(self, *, untrusted_p1):
        # this raises ValueError if untrusted_p1 is not one of the enum values
        p1 = const.U2F_AUTH(untrusted_p1)
        return p1

    def hexdump_request_data(self):
        return util.hexlify_with_parition(self.request_data,
            const.U2F_NONCE_SIZE)

class CommandAPDUAuthenticate(CommandAPDU):
    '''U2F_AUTHENTICATE'''
    APDU_INS = const.U2F.AUTHENTICATE
    APDU_RESPONSE = ResponseAPDUAuthenticate

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 1 is for key_handle length octet
        offset = const.U2F_NONCE_SIZE + const.U2F_APPID_SIZE + 1
        self.key_handle = self.request_data[offset:]

    def get_argument_for_key(self):
        '''Argument for qrexec call to identify the key'''
        # use first 128 bits of SHA-256, or 32 hexadecimal digits
        return hashlib.sha256(self.key_handle).hexdigest()[:32]

    def verify_p1(self, *, untrusted_p1):
        # this raises ValueError if untrusted_p1 is not one of the enum values
        p1 = const.U2F_AUTH(untrusted_p1)
        return p1

    def verify_request_data(self, *, untrusted_request_data):
        kh_offset = const.U2F_NONCE_SIZE + const.U2F_APPID_SIZE
        kh_len = untrusted_request_data[kh_offset]  # raises IndexError
        assert kh_len <= const.MAX_KH_SIZE
        assert len(untrusted_request_data) == kh_offset + 1 + kh_len
        request_data = untrusted_request_data
        return request_data

    def hexdump_request_data(self):
        return util.hexlify_with_parition(self.request_data,
            const.U2F_NONCE_SIZE, const.U2F_APPID_SIZE, 1)

class CommandAPDUVersion(CommandAPDU):
    '''U2F_VERSION'''
    APDU_INS = const.U2F.VERSION
    APDU_RESPONSE = ResponseAPDUVersion

    def verify_request_data(self, *, untrusted_request_data):
        assert not untrusted_request_data
        return b''


# pylint: disable=too-few-public-methods,missing-docstring

class U2FHIDInitResp(ctypes.BigEndianStructure):
    _pack_ = True
    _fields_ = (
        ('_nonce', ctypes.c_uint8 * 8),
        ('cid', ctypes.c_uint32),
        ('version', ctypes.c_uint8),
        ('major', ctypes.c_uint8),
        ('minor', ctypes.c_uint8),
        ('build', ctypes.c_uint8),
        ('caps', ctypes.c_uint8),
    )
    nonce = util.raw_data('_nonce')

assert ctypes.sizeof(U2FHIDInitResp) == 17

class _U2FHIDPacketInit(ctypes.BigEndianStructure):
    _pack_ = True
    _fields_ = (
        ('type', ctypes.c_uint8, 1),
        ('cmd', ctypes.c_uint8, 7),
        ('bcnt', ctypes.c_uint16),
        ('data', ctypes.c_uint8 * 57),
    )

class _U2FHIDPacketCont(ctypes.BigEndianStructure):
    _fields_ = (
        ('type', ctypes.c_uint8, 1),
        ('seq', ctypes.c_uint8, 7),
        ('data', ctypes.c_uint8 * 59),
    )

class _U2FHIDPacketPayloadUnion(ctypes.Union):
    _fields_ = (
        ('init', _U2FHIDPacketInit),
        ('cont', _U2FHIDPacketCont),
    )
# ctypes authors did forget about unions when implementing _OTHER_ENDIAN
_U2FHIDPacketPayloadUnion.__ctype_be__ = _U2FHIDPacketPayloadUnion

class U2FHIDPacket(ctypes.BigEndianStructure):
    # NOTE TO SELF:
    # do not use raw_data, only the upper layer knows the size of the data
    _anonymous_ = ('u',)
    _fields_ = (
        ('cid', ctypes.c_uint32),
        ('u', _U2FHIDPacketPayloadUnion),
    )

    def is_init(self):
        ''':py:obj:`True` if TYPE_INIT, :py:obj:`False` otherwise.'''
        # it does not matter which union member we choose
        return self.init.type == const.U2FHID_TYPE.INIT

    def __repr__(self):
        if self.is_init():
            meta = 'cmd={!s}, bcnt={}'.format(
                const.U2FHID(self.init.cmd), self.init.bcnt)
            data = self.init.data
        else:
            meta = 'seq={}'.format(self.cont.seq)
            data = self.cont.data

        return '{}(cid={:#08x}, type={!s}, {}, data={})'.format(
            type(self).__name__, self.cid, const.U2FHID_TYPE(self.init.type),
            meta, util.hexlify(data))

    def hexdump(self):
        if self.is_init():
            return '{:08x} {:02x} {:04x} {}'.format(self.cid,
                (self.init.type << 7) + self.init.cmd, self.init.bcnt,
                util.hexlify(self.init.data))
        else:
            return '{:08x}  {:02x} {}'.format(self.cid,
                (self.cont.type << 7) + self.cont.seq,
                util.hexlify(self.cont.data))

assert ctypes.sizeof(U2FHIDPacket) == const.HID_FRAME_SIZE


# pylint: enable=too-few-public-methods,missing-docstring

def get_der_length(*, untrusted_der_data):
    '''Parse X.509 or ECDSA signature and return its length

    :param bytes untrusted_der_data: DER-encoded structured ASN.1 object
        (like X.509 or ECDSA signature)
    '''
    # Both X.509 and ECDSA signatures are in principle DER-encoded
    # ASN.1 objects. This is nice. We all love ASN.1.

    untrusted_t, untrusted_l = untrusted_der_data[:2]
    assert untrusted_t == 0x30  # universal (0), structured(1), sequence(16)

    if untrusted_l & 0x80 == 0:  # this is the length
        return untrusted_l + 2

    if untrusted_l == 0x81:  # length in one following octet
        return untrusted_der_data[2] + 3

    elif untrusted_l == 0x82:  # length in two following octets
        return util.u16n_read(untrusted_der_data, 2) + 4

    # longer than 65535 octets, or not DER at all
    raise AssertionError()

    # Wasn't that simple? The world is a happier place with ASN.1.


@contextlib.contextmanager
def apdu_error_responder(stream=sys.stdout.buffer, exit_on_error=True):
    '''On error, write an appropriate response APDU to the stream.'''
    try:
        yield

    except APDUError as err:
        # pylint: disable=no-member
        stream.write(bytes(err.APDU_SW))
        stream.close()

        if exit_on_error:
            sys.exit(1)
