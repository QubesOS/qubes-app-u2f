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
    On standard input a complete CTAP request (CBOR) command is expected.
    On standard output, CTAP response (CBOR) is returned.

    Disabling this option essentially disables the entire CTAP2 protocol, while the previous version (U2F) will continue to work without any changes.

Bugs
----

To enable debug log, touch either of those files:

- ``/etc/qubes/ctap-debug-enable``

- ``/usr/local/etc/qubes/ctap-debug-enable``

The log will be sent to syslog AUTH facility.

To disable ``CTAP2``,  touch either of those files:

- ``/etc/qubes/ctap2-disable``

- ``/usr/local/etc/qubes/ctap2-disable``

Author
------

| Piotr Bartman <prbartman@invisiblethingslab.com>
