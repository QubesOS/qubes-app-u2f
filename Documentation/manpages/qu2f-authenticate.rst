.. program:: qu2f-register

:program:`qu2f-authenticate` -- U2F_AUTHENTICATE qrexec call
============================================================

Synopsis
--------

:command:`qu2f-authenticate` [*KEYHANDLEID*]

Description
-----------

This program handles ``u2f.Authenticate`` qrexec call. As the argument there
should be first 128 bits of SHA-256 digest over key handle, as hexadecimal
digits. The program verifies if it matches the key handle included in the APDU.

Environment variables
---------------------

.. envvar:: QREXEC_SERVICE_ARGUMENT

    Alternative way of providing Key Handle ID. The program accepts both ways,
    and you need to provide either one. This is for easy testing.

Qrexec calls
------------

``u2f.Authenticate``
    On standard input a complete command APDU is expected. On standard output,
    response APDU is returned.

Varia
-----

A Python oneliner for generating key handle hash:

.. code-block:: python

    hashlib.sha256(key_handle).hexdigest()[:32]


Bugs
----

To enable debug log, touch either of those files:

- ``/etc/qubes/u2f-debug-enable``

- ``/usr/local/etc/qubes/u2f-debug-enable``

The log will be sent to syslog AUTH facility.

Author
------

| Wojtek Porczyk <woju@invisiblethingslab.com>

.. vim: tw=80
