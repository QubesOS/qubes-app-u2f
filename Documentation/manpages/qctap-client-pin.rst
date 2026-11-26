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
    if it does not match. Possible values:

    - ``get-pin-retries``
    - ``get-key-agreement``
    - ``set-pin``
    - ``change-pin``
    - ``get-token-using-pin-legacy``
    - ``get-token-using-uv``
    - ``get-uv-retries``
    - ``get-token-using-pin``
    - ``subcmd-N`` for any other subcommand number ``N``

    ``set-pin`` and ``change-pin`` let a qube set or change the PIN of the
    device. To let a qube use the PIN but not change it, allow everything but
    those two, for example::

        ctap.ClientPin +set-pin @anyvm @anyvm deny
        ctap.ClientPin +change-pin @anyvm @anyvm deny
        ctap.ClientPin * work sys-usb allow

    The proxy checks ``get-pin-retries`` to know if the PIN can be used.

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
