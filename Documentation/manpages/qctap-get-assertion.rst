.. program:: qctap-get-assertion

:program:`qctap-get-assertion` -- CTAP_GET_ASSERTION qrexec call
================================================================

Synopsis
--------

:command:`qctap-get-assertion` [*CREDENTIAL_ID_HASH*]

Description
-----------

This program handles ``u2f.Authenticate`` qrexec call. As the argument there
should be first 128 bits of SHA-256 digest over credential ID, as hexadecimal
digits. The program verifies if it matches the credential ID included in the
request.
For backward compatibility, the qrexec call name remains unchanged and is the same for both `u2f Authenticate` and `fido2 GetAssertion` requests.

Environment variables
---------------------

.. envvar:: QREXEC_SERVICE_ARGUMENT

    Alternative way of providing credential ID. The program accepts both ways,
    and you need to provide either one. This is for easy testing.

Qrexec calls
------------

``u2f.Authenticate``
    On standard input a complete CTAP request (APDU/CBOR) command is expected.
    On standard output, CTAP response (APDU/CBOR) is returned.

Varia
-----

A Python oneliner for generating key handle hash:

.. code-block:: python

    hashlib.sha256(credential_id).hexdigest()[:32]


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
