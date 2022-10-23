.. program:: qctap-make-credential

:program:`qctap-make-credential` -- CTAP_MAKE_CREDENTIAL qrexec call
====================================================

Synopsis
--------

:command:`qctap-make-credential`

Description
-----------

This program handles ``ctap.MakeCredential`` qrexec call.

Options
-------

None.

Qrexec calls
------------

``ctap.MakeCredential``
    On standard input a complete CTAP request command (APDU/CBOR) is expected.
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
| Wojtek Porczyk <woju@invisiblethingslab.com>
