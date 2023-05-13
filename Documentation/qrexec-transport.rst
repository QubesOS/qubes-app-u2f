CTAP qrexec transport
====================

This is a formal specification for encapsulating CTAP communication [`FIDO2`_]
in qrexec. It can be viewed as another method like the most common HID transport
[`CTAPHID`_] or NFC.

The calls
---------

* ``ctap.MakeCredential``
* ``ctap.GetAssertion+CREDID``
* ``ctap.GetInfo``
* ``ctap.ClientPin``
* ``ctap.vnd.VENDOR.COMMAND``

Raw ISO 7816-compliant command APDU with extended length encoding should be
supplied on standard input. The response APDU will arrive on standard output.

`CREDID` is first 128 bits of SHA-256 digest over key handle expressed as
hexadecimal digits, lower case.

`VENDOR` and `COMMAND` are vendor-invented strings. The vendor is also free to
specify an argument to the qrexec call.

A note about encapsulation transparency
---------------------------------------

The transport transparency is explicitly disclaimed. This transport can and will
inspect the APDUs and may respond with status words that did not originate from
the actual token.

.. _FIDO2:
    https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html
.. _CTAPHID:
    https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#transport-specific-bindings

.. vim: tw=80 ts=4 sts=4 sw=4 et
