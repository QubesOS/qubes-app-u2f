#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2022 Piotr Bartman <prbartman@invisiblethingslab.com>
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

"""Qrexec call: ctap2.Pin"""

import asyncio
import sys

from qubesu2f import sys_usb
from qubesu2f.sys_usb.mux import mux
# pylint: disable=duplicate-code

def main():
    """Main routine of ``ctap2.Pin`` qrexec call"""

    sys_usb.setup_logging()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(mux(sys.stdin.buffer.read()))


if __name__ == '__main__':
    sys.exit(main())