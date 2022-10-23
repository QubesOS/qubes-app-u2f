#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2023  Piotr Bartman <prbartman@invisiblethingslab.com>
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

"""Common logging features for sys-usb entries."""

import logging
import logging.handlers
import pathlib

# touch any of those to increase logging verbosity
DEBUG_ENABLE_PATHS = [
    '/etc/qubes/ctap-debug-enable',
    '/usr/local/etc/qubes/ctap-debug-enable',
]


def setup_logging(debug=None):
    """Setup logging

    The tools log to syslog (AUTH facility).
    """
    logging.basicConfig(format='%(name)s %(message)s',
        handlers=[logging.handlers.SysLogHandler(address='/dev/log',
            facility=logging.handlers.SysLogHandler.LOG_AUTH)])

    if debug is None:
        debug = any(pathlib.Path(path).exists() for path in DEBUG_ENABLE_PATHS)
    if debug:
        logging.root.setLevel(logging.NOTSET)
