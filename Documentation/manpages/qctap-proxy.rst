.. program:: qctap-proxy

:program:`qctap-proxy` -- CTAP proxy daemon
=========================================

Synopsis
--------

:command:`qctap-proxy`
[--help]
[--verbose]
[--quiet]
[--hid-name *NAME*]
[--hid-phys *PHYS*]
[--hid-serial *SERIAL*]
[--hid-vendor *VENDOR*]
[--hid-product *PRODUCT*]
[--hid-version *VERSION*]
[--hid-bus *BUS*]
[--hid-country *COUNTRY*]
[--hid-rdesc *DESCRIPTOR*]
[*VMNAME*]

Description
-----------

This daemon emulates a HID device which forwards CTAP requests over qrexec to
a real device in a domain which holds USB host.

Options
-------

Basic options
^^^^^^^^^^^^^

.. option:: --help, -h

    Show help message and exit.

.. option:: --verbose, -v

    Increase verbosity. (:py:mod:`logging` loglevel += 10)

.. option:: --quiet, -q

    Decrease verbosity. (:py:mod:`logging` loglevel -= 10)

HID lowlevel configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^

The following options fill the device struct with custom values. The default
values are sane.

.. code-block:: c

    struct uhid_create2_req {
           __u8 name[128];
           __u8 phys[64];
           __u8 uniq[64];
           __u16 rd_size;
           __u16 bus;
           __u32 vendor;
           __u32 product;
           __u32 version;
           __u32 country;
           __u8 rd_data[HID_MAX_DESCRIPTOR_SIZE];
    } __attribute__((__packed__));

.. option:: --hid-name <NAME>

    The ``name`` field (at most 128 bytes).

.. option:: --hid-phys <PHYS>

    The ``phys`` field (at most 64 bytes).

.. option:: --hid-serial <SERIAL>, --hid-uniq <SERIAL>

    The ``uniq`` field, which is a serial number (at most 64 bytes).

.. option:: --hid-vendor <VENDOR>

    The ``vendor`` field, given as 4 hexadecimal digits.

.. option:: --hid-product <PRODUCT>

    The ``product`` field, given as 4 hexadecimal digits.

.. option:: --hid-version <PRODUCT>

    The ``version`` field, given as decimal number.

.. option:: --hid-bus <BUS>

    The ``bus`` field, given as decimal number or symbolic name like
    ``BLUETOOTH``. The choices are:
    ``PCI`` (1),
    ``ISAPNP`` (2),
    ``USB`` (3),
    ``HIL`` (4),
    ``BLUETOOTH`` (5),
    ``VIRTUAL`` (6),
    ``ISA`` (16),
    ``I8042`` (17),
    ``XTKBD`` (18),
    ``RS232`` (19),
    ``GAMEPORT`` (20),
    ``PARPORT`` (21),
    ``AMIGA`` (22),
    ``ADB`` (23),
    ``I2C`` (24),
    ``HOST`` (25),
    ``GSC`` (26),
    ``ATARI`` (27),
    ``SPI`` (28),
    ``RMI`` (29),
    ``CEC`` (30),
    ``INTEL_ISHTP`` (31).

    The default is ``BLUETOOTH`` (5), because of compatibility issues with
    hidapi's hidraw backend.

.. option:: --hid-country <COUNTRY>

    The ``country`` field, given as decimal number.

.. option:: --hid-rdesc <DESCRIPTOR>, --hid-rd <DESCRIPTOR>

    The ``rd_data`` field, a report descriptor. The ``rd_size`` will be set to
    the correct value.

    Careful with this one, because it is this value by which the browser
    recognizes the device.

Qrexec calls
------------

``u2f.Register``
    This is the call used for the CTAP_MAKE_CREDENTIA call. It is handled by
    :manpage:`qctap-make-credential(1)`.

``u2f.Authenticate``
    This is the call used for the CTAP_GET_ASSERTION call. It is handled by
    :manpage:`qctap-get-assetion(1)`.

``ctap.ClientPin``
    This is the call used for the CTAP_MAKE_CREDENTIA call. It is handled by
    :manpage:`qctap-client-pin(1)`.

``ctap.GetInfo``
    This is the call used for the CTAP_GET_Info call. It is handled by
    :manpage:`qctap-get-info(1)`.

Author
------

| Wojtek Porczyk <woju@invisiblethingslab.com>

.. vim: tw=80
