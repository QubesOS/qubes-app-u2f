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

# pylint: disable=missing-docstring

import hashlib
import os
import sys
import unittest

from .. import tests
from ..tools import qu2f_authenticate

class TC_00_Tools_Authenticate(unittest.TestCase):
    @staticmethod
    def get_capdu_with_argument():
        key_handle = os.urandom(0x40)
        capdu = tests.get_capdu_authenticate(key_handle=key_handle)
        argument = hashlib.sha256(key_handle).hexdigest()[:32]
        return capdu, argument

    def test_000_key_handle_match(self):
        capdu, argument = self.get_capdu_with_argument()

        # XXX does unittest.mock support async functions?
        apdu_muxed = None
        async def mux(apdu):
            nonlocal capdu, apdu_muxed
            apdu_muxed = bytes(apdu) == bytes(capdu)

        with tests.mocked_stdio(bytes(capdu)):
            retcode = qu2f_authenticate.main([argument], mux=mux)
            self.assertIn(retcode, (None, 0), 'main function failed')
            self.assertFalse(sys.stdout.buffer.getvalue())
            self.assertTrue(apdu_muxed)

    def test_001_key_handle_mismatch(self):
        capdu, argument = self.get_capdu_with_argument()
        false_argument = str(reversed(argument))
        assert argument != false_argument

        # XXX does unittest.mock support async functions?
        apdu_muxed = None
        async def mux(apdu):
            nonlocal capdu, apdu_muxed
            apdu_muxed = bytes(apdu) == bytes(capdu)

        with tests.mocked_stdio(bytes(capdu)):
            retcode = qu2f_authenticate.main([false_argument], mux=mux)
            assert retcode > 0 or sys.stdout.buffer.getvalue()[0] & 0xf0 == 0x60
