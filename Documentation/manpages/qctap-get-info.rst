.. program:: qctap-get-info

:program:`qctap-get-info` -- CTAP_GET_INFO qrexec call
============================================================

Synopsis
--------

:command:`qctap-get-info`

Description
-----------

This program handles ``ctap.GetInfo`` qrexec call.

Options
-------

None.

Qrexec calls
------------

``ctap.GetInfo``
    On standard input a complete CTAP request (APDU/CBOR) command is expected.
    On standard output, CTAP response (APDU/CBOR) is returned.

Bugs
----

To enable debug log, touch either of those files:

- ``/etc/qubes/ctap-debug-enable``

- ``/usr/local/etc/qubes/ctap-debug-enable``

The log will be sent to syslog AUTH facility.

To disable ``CTAP1`` / ``CTAP2``,  touch either of those files:

- ``/etc/qubes/ctap{1, 2}-disable``

- ``/usr/local/etc/qubes/ctap{1, 2}-disable``

Author
------

| Piotr Bartman <prbartman@invisiblethingslab.com>