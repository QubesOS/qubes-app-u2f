.. program:: qctap-client-pin

:program:`qctap-client-pin` -- CTAP_CLIENT_PIN qrexec call
============================================================

Synopsis
--------

:command:`qctap-client-pin`

Description
-----------

This program handles ``ctap.ClientPin`` qrexec call.

Options
-------

None.

Qrexec calls
------------

``ctap.ClientPin``
    On standard input a complete CTAP request (CBOR) command is expected.
    On standard output, CTAP response (CBOR) is returned.

    Disabling this policy is fine only when our device does not support PIN at all. Otherwise, we will still be prompted for a PIN, but the user verification will fail.

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
