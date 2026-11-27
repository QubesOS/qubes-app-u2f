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

``ctap.ClientPin+SUBCOMMAND``
    On standard input a complete CTAP request (CBOR) command is expected.
    On standard output, CTAP response (CBOR) is returned.

    ``SUBCOMMAND`` is the PIN subcommand of the request. The request is refused
    if it is missing, does not match, or names an unknown subcommand. Possible
    values:

    - ``get-pin-retries``
    - ``get-key-agreement``
    - ``set-pin``
    - ``change-pin``
    - ``get-token-using-pin-legacy``
    - ``get-token-using-uv``
    - ``get-uv-retries``
    - ``get-token-using-pin``

    ``set-pin`` and ``change-pin`` let a qube set or change the PIN of the
    device. To let a qube use the PIN but not change it, allow everything but
    those two, for example::

        ctap.ClientPin +set-pin @anyvm @anyvm deny
        ctap.ClientPin +change-pin @anyvm @anyvm deny
        ctap.ClientPin * work sys-usb allow

    This does not stop a qube that may use the PIN from blocking it: it can send
    wrong PINs to ``get-token-using-pin-legacy`` or ``get-token-using-pin``
    until no retries are left. In the same way, ``get-token-using-uv`` can use
    up the retries of a built-in user verification, such as a fingerprint
    reader.

    If ``get-pin-retries`` is denied, the qube is told the device has no PIN.

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
