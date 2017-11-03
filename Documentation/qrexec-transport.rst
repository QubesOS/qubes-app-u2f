U2F qrexec transport
====================

This is a formal specification for encapsulating U2F messages [`U2FRawMsgs`_] in
qrexec. It can be viewed as another method like the most common
HID transport [`U2FHID`_] or NFC.

The calls
---------

* ``u2f.Register``
* ``u2f.Authenticate+KEYID``
* ``u2f.vnd.VENDOR.COMMAND``

There is no equivalent of ``U2F_VERSION``, although ``u2f.Version`` is reserved
for future use. If full protocol compliance is required, it is a responsibility
of the frontend to reply to such message.

Raw ISO 7816-compliant command APDU with extended length encoding should be
supplied on standard input. The response APDU will arrive on standard output.

`KEYID` is first 128 bits of SHA-256 digest over key handle expressed as
hexadecimal digits, lower case.

`VENDOR` and `COMMAND` are vendor-invented strings. The vendor is also free to
specify an argument to the qrexec call.

A note about encapsulation transparency
---------------------------------------

The transport transparency is explicitly disclaimed. This transport can and will
inspect the APDUs and may respond with status words that did not originate from
the actual token.

.. _U2FOverview:
    https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html
.. _U2FRawMsgs:
    https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
.. _U2FHID:
    https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html

.. vim: tw=80 ts=4 sts=4 sw=4 et
